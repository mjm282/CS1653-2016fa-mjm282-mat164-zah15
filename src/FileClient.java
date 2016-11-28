/* FileClient provides all the client functionality regarding the file server */

import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.*;
import java.security.*;
import java.math.BigInteger;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.CipherOutputStream;

public class FileClient extends Client implements FileClientInterface {

	//TODO: Server authentication
	//make custom connect() class with args server, port, and token
	/* // Create socket
			sock = new Socket(server, port);

			// Set up I/O
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
	*/
	//recieve public key from server, SHA-256 hash it
		//contact fileserver admin offline to verify that it's correct
	//generate a challenge and send to server
	//Wait for challenge to be sent back decrypted, verify it's correct
		//for security maybe do hash stuff
	//send token (encrypted with AES key) as well as generated AES key (encrypted with server public key)
	private Key sessionKey;
	private IvParameterSpec IV = null;
	private byte[] aesTok = null;

	private Serializer ser = new Serializer();

	ArrayList<Object> macList = null;
	int checkCount = -1;
	int counterFS = -1;
	int counterFC = -1;

	public boolean connect(final String server, final int port, UserToken token, PublicKey groupPubKey) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try{
			sock = new Socket(server, port);

			// Set up I/O
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			counterFC = 0;

			Key sPubKey = null;

			Envelope message = null, response = null;

			//wait for the server to send their public key
			response = (Envelope)input.readObject();
			checkCount = (int)response.getObjContents().get(1);
			if(counterFS >= checkCount) //Check to make sure counter is greaterthan previous counter
			{
				response = new Envelope("FAIL");
				response.addObject(counterFC);
				output.writeObject(response);
				counterFC++;
			}
			else
			{
				counterFS = checkCount;
			}

			if(response.getMessage().equals("SHAKE")){
				//get the server's public key
				sPubKey = (PublicKey)response.getObjContents().get(0);
				//calculate SHA-256 hash
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] keyBytes = sPubKey.getEncoded();
				md.update(keyBytes);
				byte[] digest = md.digest();
				System.out.println("SHA-256 Hash of public key is:");
				for(int i = 0; i < digest.length; i++)
				{
					System.out.print(digest[i]);
				}
				System.out.println("\nContact File Server to verify.");

				//Genereate challenge for fileserver
				Random chalRand = new Random();
				BigInteger C1 = new BigInteger(256, chalRand);
				byte[] ciphC1 = encryptChalRSA(C1, sPubKey);

				//Send encrypted challenge
				message = new Envelope("OK");
				message.addObject(ciphC1);
				message.addObject(encryptCounterRSA(counterFC, sPubKey));
				output.writeObject(message);
				counterFC++;

				//Receive decrypted challenge
				response = (Envelope)input.readObject();
				checkCount = (int)response.getObjContents().get(1);
				if(counterFS >= checkCount)
				{
					message = new Envelope("FAIL");
					message.addObject(encryptCounterRSA(counterFC, sPubKey));
					output.writeObject(message);
					counterFC++;
				}
				else
				{
					counterFS = checkCount;
				}
				if(response.getMessage().equals("OK"))
				{
					BigInteger rC1 = (BigInteger)response.getObjContents().get(0);
					//Verify chalenge
					if(rC1.equals(C1)) //If challenge matches
					{
						//Generate AES key
						sessionKey = genSessionKey();

						//Encrypt AES key
						byte[] rsaSessionKey = encryptAESKeyRSA(sessionKey, sPubKey);

						//serialize token
						Serializer byteTok = new Serializer();
						byte[] serTok = byteTok.serialize(token);

						//generate IV
						SecureRandom ivRand = new SecureRandom();
						byte[] ivBytes = new byte[16];
						ivRand.nextBytes(ivBytes);
						IV = new IvParameterSpec(ivBytes);

						//Encrpyt token with AES Key
						aesTok = encryptAES(serTok, sessionKey, IV);

						//Send token encrypted with AES key and AES key encrypted with RSA public key
						message = new Envelope("OK");
						message.addObject(rsaSessionKey);//0
						message.addObject(aesTok);//1
						message.addObject(ivBytes); //2
						message.addObject(groupPubKey); //3, The public key to verifiy the token
						message.addObject(encryptAEScounter(counterFC, sessionKey, IV)); //4
						output.writeObject(message);
						counterFC++;
					}
					else
					{
						response = new Envelope("FAIL");
						response.addObject(encryptCounterRSA(counterFC, sPubKey));
						output.writeObject(response);
						counterFC++;
					}
				}
			}
			response = (Envelope)input.readObject();
			checkCount = decryptAEScounter((byte[])response.getCounter(), sessionKey, IV);
			macList = new ArrayList<Object>(response.getObjContents().subList(0, response.getObjContents().size()-1));
			if(counterFS >= checkCount)
			{
				message = new Envelope("FAIL");
				message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				output.writeObject(message);
				counterFC++;
			}
			else if(response.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
			{
				message = new Envelope("FAIL-BAD-HMAC");
				message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				output.writeObject(message);
				counterFC++;
			}
			else
			{
				counterFS = checkCount;
			}
			if(response.getMessage().equals("OK"))
			{
				//The token sent was verified
				return isConnected();
			}
			else
			{
				//Return false because the token wasn't verified
				return false;
			}
		}
		catch(Exception e){
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			// Returning false becosue something bad happened
			return false;
		}
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath = "";
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		Envelope message = null;
			try {
				env.addObject(encryptAES(remotePath.getBytes(), sessionKey, IV));
			} catch (Exception e) {
				e.printStackTrace();
			}
	    env.addObject(aesTok);
	    try {
			env.addObject(encryptAEScounter(counterFC, sessionKey, IV));
			env.addObject(generateHMAC(env.getObjContents(), sessionKey));
			output.writeObject(env);
			counterFC++;
		    env = (Envelope)input.readObject();
				checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
				macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
				if(counterFS >= checkCount)
				{
					message = new Envelope("FAIL");
					message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
					message.addObject(generateHMAC(message.getObjContents(), sessionKey));
					output.writeObject(message);
					counterFC++;
				}
				else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
				{
					message = new Envelope("FAIL-BAD-HMAC");
					message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
					message.addObject(generateHMAC(message.getObjContents(), sessionKey));
					output.writeObject(message);
					counterFC++;
				}
				else
				{
					counterFS = checkCount;
				}

			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
				File file = new File(destFile + ".enc");
				Envelope message = null;
			    try {


				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success
							try {
								env.addObject(encryptAES(sourceFile.getBytes(), sessionKey, IV));
							} catch (Exception e) {
								e.printStackTrace();
							}
					    env.addObject(aesTok);
							env.addObject(encryptAEScounter(counterFC, sessionKey, IV));
							env.addObject(generateHMAC(env.getObjContents(), sessionKey));
					    output.writeObject(env);
							counterFC++;

					    env = (Envelope)input.readObject();
							checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
							macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
							if(counterFS >= checkCount)
							{
								message = new Envelope("FAIL");
								message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
								message.addObject(generateHMAC(message.getObjContents(), sessionKey));
								output.writeObject(message);
								counterFC++;
							}
							else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
							{
								message = new Envelope("FAIL-BAD-HMAC");
								message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
								message.addObject(generateHMAC(message.getObjContents(), sessionKey));
								output.writeObject(message);
								counterFC++;
							}
							else
							{
								counterFS = checkCount;
							}

						boolean meta = true;

						while (env.getMessage().compareTo("CHUNK")==0) {
								try
								{
									if(meta)
									{
										meta = false;
										File mFile = new File(destFile + ".meta");
										FileOutputStream mFos = new FileOutputStream(mFile);
										mFile.createNewFile();
										mFos.write((byte[])decryptAES((byte[])env.getObjContents().get(0), sessionKey, IV), 0, 120);
										mFos.close();
									}
									else
									{
										fos.write((byte[])decryptAES((byte[])env.getObjContents().get(0), sessionKey, IV), 0, (Integer)ser.deserialize(decryptAES((byte[])env.getObjContents().get(1), sessionKey, IV)));
									}
								} catch (Exception e) {
									e.printStackTrace();
								}
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								env.addObject(encryptAEScounter(counterFC, sessionKey, IV));
								env.addObject(generateHMAC(env.getObjContents(), sessionKey));
								output.writeObject(env);
								counterFC++;

								env = (Envelope)input.readObject();
								checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
								macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
								if(counterFS >= checkCount)
								{
									message = new Envelope("FAIL");
									message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
									message.addObject(generateHMAC(message.getObjContents(), sessionKey));
									output.writeObject(message);
									counterFC++;
								}
								else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
								{
									message = new Envelope("FAIL-BAD-HMAC");
									message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
									message.addObject(generateHMAC(message.getObjContents(), sessionKey));
									output.writeObject(message);
									counterFC++;
								}
								else
								{
									counterFS = checkCount;
								}

						}
						fos.close();

					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								env.addObject(encryptAEScounter(counterFC, sessionKey, IV));
								env.addObject(generateHMAC(env.getObjContents(), sessionKey));
								output.writeObject(env);
								counterFC++;
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;
						}
				    }

				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }


			    } catch (IOException e1) {

			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;


				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");

			 Serializer byteTok = new Serializer();
			 byte[] serTok = byteTok.serialize(token);
			 aesTok = encryptAES(serTok, sessionKey, IV);
			 message.addObject(aesTok); //Add requester's encrypted token
			 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
			 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
			 output.writeObject(message);
			 counterFC++;

			 e = (Envelope)input.readObject();
			 checkCount = decryptAEScounter((byte[])e.getCounter(), sessionKey, IV);
			 macList = new ArrayList<Object>(e.getObjContents().subList(0, e.getObjContents().size()-1));
			 if(counterFS >= checkCount)
			 {
				 message = new Envelope("FAIL");
				 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				 output.writeObject(message);
				 counterFC++;
			 }
			 else if(e.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
			 {
				 message = new Envelope("FAIL-BAD-HMAC");
				 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				 output.writeObject(message);
				 counterFC++;
			 }
			 else
			 {
				 counterFS = checkCount;
			 }

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				return (List<String>)ser.deserialize(decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV)); //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token, Key groupKey, int keyNum) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			//  Serializer byteTok = new Serializer();
			//  byte[] serTok = byteTok.serialize(token);
			//  aesTok = encryptAES(serTok, sessionKey, IV);
			 message.addObject(encryptAES(destFile.getBytes(), sessionKey, IV));
			 message.addObject(encryptAES(group.getBytes(), sessionKey, IV));
			 message.addObject(aesTok); //Add requester's token
			 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
			 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
			 output.writeObject(message);
			 counterFC++;


			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();
			 checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
			 macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
			 if(counterFS >= checkCount)
			 {
				 message = new Envelope("FAIL");
				 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				 output.writeObject(message);
				 counterFC++;
			 }
			 else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
			 {
				 message = new Envelope("FAIL-BAD-HMAC");
				 message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				 message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				 output.writeObject(message);
				 counterFC++;
			 }
			 else
			 {
				 counterFS = checkCount;
			 }

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

			 //sends the key number and IV first before transmitting any file contents

			 //generate an IV for upload, each file has it's own IV that will be attatched to the file
			SecureRandom ivRand = new SecureRandom();
            byte[] ivBytes = new byte[16];
            ivRand.nextBytes(ivBytes);
			IvParameterSpec fileIV = new IvParameterSpec(ivBytes);

			Serializer ser = new Serializer();

			byte[] startBytes = new byte [120];
			byte[] intBytes = new byte[4];
			byte[] groupBytes = new byte[100]; //imposes a 50 character limit on group names, which I feel is PLENTY

			//intBytes = (byte[]) ser.serialize(keyNum);
			intBytes[0] = (byte) (keyNum >> 24);
			intBytes[1] = (byte) (keyNum >> 16);
			intBytes[2] = (byte) (keyNum >> 8);
			intBytes[3] = (byte) (keyNum);
			groupBytes = group.getBytes();

			for(int i = 0; i < 20; i++)
			{
				if(i < 4)
				{
					startBytes[i] = intBytes[i];
					// System.out.println(startBytes[i]);
				}
				else if (i < 20)
				{
					startBytes[i] = ivBytes[i-4];
					// System.out.println(startBytes[i]);
				}
			}


			for(int i = 0; i < groupBytes.length; i++)
			{
				startBytes[i+20] = groupBytes[i];
			}

			boolean firstChunk = true;
			Cipher encCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			encCipher.init(Cipher.ENCRYPT_MODE, groupKey, fileIV);
			File encFile = new File(sourceFile + ".enc");
			encFile.createNewFile();
			FileOutputStream fOut = new FileOutputStream(encFile);
			CipherOutputStream cOut = new CipherOutputStream(fOut, encCipher);
			int read = 0;
			byte[] encBuf = new byte[4096];
			while((read = fis.read(encBuf)) >= 0)
			{
				cOut.write(encBuf, 0, read);
			}
			fis.close();
			cOut.flush();
			cOut.close();

			FileInputStream encFis = new FileInputStream(encFile);

			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n;
					if(firstChunk)
					{
						for(int i = 0; i < 120; i++)
						{
							buf[i] = startBytes[i];
						}

						n = 120;
						//firstChunk = false;

						//byte[] tempBuf = new byte[3976]
						//n = fis.read(tempBuf);

						//for(int i = 0; i < tempBuf.length; i++)
						//{
						//	buf[i+120] =
						//}

						// byte[] tmpBuf = new byte[3960];
						// n = fis.read(tmpBuf);
						// tmpBuf = encryptAES(tmpBuf, groupKey, fileIV);
						// for(int i = 0; i < tmpBuf.length; i++)
						// {
							// buf[i+120] = tmpBuf[i];
						// }

						// for(int i = 0; i < buf.length; i++)
						// {
							// System.out.print(buf[i]);
						// }
					}
					else
					{
						n = encFis.read(buf); //can throw an IOException
					}
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					if(firstChunk)
					{
						firstChunk = false;
						message.addObject(startBytes);
					}
					else
					{
						message.addObject(buf);//(encryptAES(buf, groupKey, fileIV));
						Integer nSend = new Integer(n);
						Serializer nByte = new Serializer();
						byte[] nSer = nByte.serialize(nSend);
						byte[] nAES = encryptAES(nSer, sessionKey, IV);
						message.addObject(nAES);
					}

					message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
					message.addObject(generateHMAC(message.getObjContents(), sessionKey));
					output.writeObject(message);
					counterFC++;


					env = (Envelope)input.readObject();
					checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
					macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
					if(counterFS >= checkCount)
					{
						message = new Envelope("FAIL");
						message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
						message.addObject(generateHMAC(message.getObjContents(), sessionKey));
						output.writeObject(message);
						counterFC++;
					}
					else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
					{
						message = new Envelope("FAIL-BAD-HMAC");
						message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
						message.addObject(generateHMAC(message.getObjContents(), sessionKey));
						output.writeObject(message);
						counterFC++;
					}
					else
					{
						counterFS = checkCount;
					}

			 }
			while (encFis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
				message.addObject(generateHMAC(message.getObjContents(), sessionKey));
				output.writeObject(message);
				counterFC++;

				env = (Envelope)input.readObject();
				checkCount = decryptAEScounter((byte[])env.getCounter(), sessionKey, IV);
				macList = new ArrayList<Object>(env.getObjContents().subList(0, env.getObjContents().size()-1));
				if(counterFS >= checkCount)
				{
					message = new Envelope("FAIL");
					message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
					message.addObject(generateHMAC(message.getObjContents(), sessionKey));
					output.writeObject(message);
					counterFC++;
				}
				else if(env.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
				{
					message = new Envelope("FAIL-BAD-HMAC");
					message.addObject(encryptAEScounter(counterFC, sessionKey, IV));
					message.addObject(generateHMAC(message.getObjContents(), sessionKey));
					output.writeObject(message);
					counterFC++;
				}
				else
				{
					counterFS = checkCount;
				}

				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
					encFis.close();
					encFile.delete();
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	public byte[] encryptChalRSA(BigInteger challenge, Key pubRSAkey) throws Exception
  {
  	Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
  	rsaCipher.init(Cipher.ENCRYPT_MODE, pubRSAkey);
  	byte[] byteCipherText = rsaCipher.doFinal(challenge.toByteArray());
  	return byteCipherText;
  }

	public byte[] encryptAESKeyRSA(Key aesKey, Key pubRSAkey) throws Exception
	{
		Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
  	rsaCipher.init(Cipher.ENCRYPT_MODE, pubRSAkey);
  	byte[] byteCipherText = rsaCipher.doFinal(aesKey.getEncoded());
  	return byteCipherText;
	}

  public BigInteger decryptBIRSA(byte[] cipherText, Key privRSAkey) throws Exception
  {
  	Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
  	rsaCipher.init(Cipher.DECRYPT_MODE, privRSAkey);
  	byte[] byteText = rsaCipher.doFinal(cipherText);
		BigInteger dcBI = new BigInteger(1, byteText);
  	return dcBI;
  }

	// AES Key (Turley)
	public Key genSessionKey() throws Exception
	{
		KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
		generator.init(128);
		Key myAESkey = generator.generateKey();
		return myAESkey;
	}

	public static byte[] encryptAES(byte[] plainText, Key AESkey, IvParameterSpec IV) throws Exception
	{
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aesCipher.init(Cipher.ENCRYPT_MODE, AESkey, IV);
		byte[] byteCipherText = aesCipher.doFinal(plainText);
		return byteCipherText;
	}

	public static byte[] decryptAES(byte[] cipherText, Key AESkey, IvParameterSpec IV) throws Exception
	{
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aesCipher.init(Cipher.DECRYPT_MODE, AESkey, IV);
		byte[] byteText = aesCipher.doFinal(cipherText);
		return byteText;
	}

	public byte[] encryptCounterRSA(int counter, Key pubRSAkey) throws Exception
	{
		BigInteger temp = new BigInteger(Integer.toString(counter));
		Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
		rsaCipher.init(Cipher.ENCRYPT_MODE, pubRSAkey);
		byte[] byteCipherText = rsaCipher.doFinal(temp.toByteArray());
		return byteCipherText;
	}

	public int decryptCounterRSA(byte[] cipherText, Key privRSAkey) throws Exception
	{
		Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
		rsaCipher.init(Cipher.DECRYPT_MODE, privRSAkey);
		byte[] byteText = rsaCipher.doFinal(cipherText);
		BigInteger counter = new BigInteger(1, byteText);
		return counter.intValue();
	}

	public static byte[] encryptAEScounter(int counter, Key AESkey, IvParameterSpec IV)
	{
		try{
			BigInteger temp = new BigInteger(Integer.toString(counter));
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			aesCipher.init(Cipher.ENCRYPT_MODE, AESkey, IV);
			byte[] byteCipherText = aesCipher.doFinal(temp.toByteArray());
			return byteCipherText;
		}
		catch(Exception e){
			System.err.println("Error: "+e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public static int decryptAEScounter(byte[] cipherText, Key AESkey, IvParameterSpec IV)
	{
		try{
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			aesCipher.init(Cipher.DECRYPT_MODE, AESkey, IV);
			byte[] byteText = aesCipher.doFinal(cipherText);
			BigInteger counter = new BigInteger(1, byteText);
			return counter.intValue();
		}
		catch(Exception e){
			System.err.println("Error: "+e.getMessage());
			e.printStackTrace(System.err);
			return 0;
		}
	}

	public static String generateHMAC(ArrayList<Object> message, Key macKey)
	{
		try {
			Serializer ser = new Serializer();
			byte[] messBytes = ser.serialize(message);
			byte[] keyBytes = macKey.getEncoded();
			SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA256");

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(signingKey);
			byte[] rawMac = mac.doFinal(messBytes);
			// byte[] hexForm = new Hex().encode(rawMac);
			return new String(rawMac, "UTF-8");
		}
		catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
}
