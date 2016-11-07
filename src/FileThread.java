/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
// I used an ArrayList for LFILES
import java.util.ArrayList;
import org.bouncycastle.*;
import java.security.*;
import java.math.BigInteger;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class FileThread extends Thread
{
	private final Socket socket;
	private FileServer my_fs;

	public FileThread(Socket _socket, FileServer _fs)
	{
		socket = _socket;
		my_fs = _fs;
	}

	public void run()
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Key sessionKey = null;
		IvParameterSpec IV = null;
		UserToken uToken;
		Key privKey;

		Serializer ser = new Serializer();

		//TODO file auth
		//send public key in plain text
			//in fileclient they will calculate the sha256 hash of the key
		//recieve challenge C1, decrypt it with private key
		//send back plaintext challenge
		//recieve signed, encrypted token as well as encrypted AES key
			//Set sessionKey to AES key
		//validate timestamp on token

		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			//Send public key generated from FileServer
			Envelope message = null;
			message = new Envelope("SHAKE");
			message.addObject(my_fs.getPublicKey());
			output.writeObject(message);

			//Receive challenge and decrypt with private key
			Envelope response = null;
			response = (Envelope)input.readObject();
			privKey = my_fs.getPrivateKey();
			if(response.getMessage().equals("OK"))
			{
				//get encrypted C1
				byte[] chal = (byte[])response.getObjContents().get(0);
				//decrypt C1
				BigInteger C1 = decryptBIRSA(chal, privKey);

				//Send back plaintext challenge
				message = new Envelope("OK");
				message.addObject(C1);
				output.writeObject(message);

				//wait for a response
				response = (Envelope)input.readObject();
				if(response.getMessage().equals("OK"))
				{
					byte[] rsaSessionKey = (byte[])response.getObjContents().get(0);
					byte[] aesTok = (byte[])response.getObjContents().get(1);
					byte[] ivBytes = (byte[])response.getObjContents().get(2);

					// Create IV from ivBytes
					IV = new IvParameterSpec(ivBytes);
					// And we have a session key!
					sessionKey = decryptAESKeyRSA(rsaSessionKey, privKey);
					System.out.println("session key: " + sessionKey.toString());

					// Now retrive the token
					byte[] serTok = decryptAES(aesTok, sessionKey, IV);
					// And Deserilize it
					Serializer mySerializer = new Serializer();
					uToken = (UserToken)mySerializer.deserialize(serTok);

					//generate a current timestamp to compare to the one from token
					long unixTime = System.currentTimeMillis() / 1000L;
					long tokTime = uToken.getTimestamp();

					if((unixTime - tokTime) > 600)
					{
						System.out.println("Sorry, this token is too old, terminating connection");
						socket.close();
						proceed = false;
					}

				}
			}
			else
			{
				message = new Envelope("FAIL");
				output.writeObject(message);
			}

			/*
			//Decrypt toekn and AES key
			response = (Envelope)input.readObject();
			if(response.getMessage().equals("OK"))
			{
				byte[] aesToken = (byte[])response.getObjContents().get(0);
				byte[] rsaSessionKey = (byte[])response.getObjContents().get(1);
				IvParameterSpec vec = (IvParameterSpec)response.getObjContents().get(2);

				//Decrypt sessionKey
				Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
				rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
				sessionKey = new SecretKeySpec(rsaCipher.doFinal(rsaSessionKey), "AES");


				Cipher aesCipher = Cipher.getInstance("AES", "BC");
				aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, vec);
				uToken = (UserToken)ser.deserialize(aesCipher.doFinal(aesToken));

			}
			*/

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
				    if(e.getObjContents().size() < 1)
					{
						// If the ArrayList is empty
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else // ArrayList is not empty
					{
						if(e.getObjContents().get(0) == null)
						{
							response = new Envelope("FAIL-BADTOKEN");
						}
						else
						{
							// Extract user token
							UserToken workingToken = (UserToken)ser.deserialize(decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV));

							// Lists of Files
							List<ShareFile> allFiles = FileServer.fileList.getFiles(); // Full file list from server
							List<String> userFiles = new ArrayList<String>(); // List of user's files

							if (allFiles != null) // If there are no files on the server, there is nothing for the user
							{
								for (ShareFile sf: allFiles)
								{
									if (workingToken.getGroups().contains(sf.getGroup())) // If a file is in a group the user is a member of
									{
										userFiles.add(sf.getPath() + "\t(" + sf.getOwner() + "/" + sf.getGroup() + ")");
									}
								}
							}

							response = new Envelope("OK"); // Set the response to indicate success
							byte[] serFile = ser.serialize(userFiles);
							byte[] aesFile = encryptAES(serFile, sessionKey, IV);
							response.addObject(aesFile); // Append the file list the responce
						}
					}
					output.writeObject(response); // Send back any responce
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath =  new String(decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV));
							String group =  new String(decryptAES((byte[])e.getObjContents().get(1), sessionKey, IV));
							UserToken yourToken = (UserToken)ser.deserialize(decryptAES((byte[])e.getObjContents().get(2), sessionKey, IV)); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV), 0, (Integer)ser.deserialize(decryptAES((byte[])e.getObjContents().get(1), sessionKey, IV)));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = new String(decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV));
					Token t = (Token)ser.deserialize(decryptAES((byte[])e.getObjContents().get(1), sessionKey, IV));
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(encryptAES(buf, sessionKey, IV));
								Integer nSend = new Integer(n);
								byte[] nSer = ser.serialize(nSend);
								byte[] nAES = encryptAES(nSer, sessionKey, IV);
								e.addObject(nAES);

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
							fis.close();
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = new String(decryptAES((byte[])e.getObjContents().get(0), sessionKey, IV));
					Token t = (Token)ser.deserialize(decryptAES((byte[])e.getObjContents().get(1), sessionKey, IV));
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	public byte[] encryptChalRSA(BigInteger challenge, Key pubRSAkey) throws Exception
	{
		Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
		rsaCipher.init(Cipher.ENCRYPT_MODE, pubRSAkey);
		byte[] byteCipherText = rsaCipher.doFinal(challenge.toByteArray());
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

	public Key decryptAESKeyRSA(byte[] aesKeyCiph, Key privRSAkey) throws Exception
	{
		Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
		rsaCipher.init(Cipher.DECRYPT_MODE, privRSAkey);
		byte[] AESkeyByte = rsaCipher.doFinal(aesKeyCiph);
		Key AESkey = new SecretKeySpec(AESkeyByte, "AES"); // I hope this works ...
		return AESkey;
	}

	// Decrypt for AES
	public static byte[] decryptAES(byte[] cipherText, Key AESkey, IvParameterSpec IV) throws Exception
  {
    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
    aesCipher.init(Cipher.DECRYPT_MODE, AESkey, IV);
    byte[] byteText = aesCipher.doFinal(cipherText);
    return byteText;
  }

	public static byte[] encryptAES(byte[] plainText, Key AESkey, IvParameterSpec IV) throws Exception
	{
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aesCipher.init(Cipher.ENCRYPT_MODE, AESkey, IV);
		byte[] byteCipherText = aesCipher.doFinal(plainText);
		return byteCipherText;
	}
}
