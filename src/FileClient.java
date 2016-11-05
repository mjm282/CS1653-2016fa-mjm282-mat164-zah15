/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import org.bouncycastle.*;
import java.security.*;
import java.math.BigInteger;

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

	public boolean connect(final String server, final int port, UserToken token) {
		try{
			sock = new Socket(server, port);

			// Set up I/O
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());

			Key sessionKey;

			Envelope message = null, response = null;

			message = (Envelope)input.readObject();

			if(message.getMessage().compareTo("SHAKE")==0){
				PublicKey fileKey = response.getObjContents().get(0);
				//calculate SHA-256 hash
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] keyBytes = fileKey.getEncoded();
				md.update(keyBytes);
				byte[] digest = md.digest();

				System.out.println("SHA-256 Hash of public key is: " + digest);
				System.out.println("Contact File Server to verify.");

				//Genereate challenge for fileserver
				Random chalRand = new Random();
				BigInteger chal = new BigInteger(256, chalRand);
				Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
				rsaCipher.init(Cipher.ENCRYPT_MODE, fileKey);
				byte[] cipherBI = rsaCipher.doFinal(challenge.toByteArray());

				//Send encrypted challenge
				response = new Envelope("OK");
				response.addObject(cipherBI);
				output.writeObject(response);

				//Receive decrypted challenge
				message = (Envelope)input.readObject();
				if(message.getMessage().compareTo("OK")==0)
				{
					BigInteger fileChal = (BigInteger)message.getObjContents().get(0);
					//Verify chalenge
					if(fileChal.equals(chal)) //If challenge matches
					{
						//Generate AES key
						KeyGenerator gen = KeyGenerator.getInstance("AES", "BC");
						generator.init(192);
						sessionKey = gen.generateKey();

						//Encrpyt token with AES Key
						Serializer byteTok = new Serializer();
						byte[] serTok = byteTok.Serialize(token);
						SecureRandom ivRand = new SecureRandom();
						byte[] ivBytes = new byte[16];
						ivRand.nextBytes(ivBytes);
						IvParameterSpec vec = new IvParameterSpec(ivBytes);
						byte[] aesTok;
						Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
						aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, vec);
						byte[] aesTok = aesCipher.doFinal(serTok); //This is the token encrypted with AES

						//Encrypt AES key
						byte[] rsaSessionKey;
						rsaCipher = Cipher.getInstance("RSA", "BC");
						rsaCipher.init(Cipher.ENCRYPT_MODE, fileKey)
						rsaSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

						//Send token encrypted with AES key and AES key encrypted with RSA public key
						response = new Envelope("OK")
						response.addObject(aesTok);
						response.addObject(rsaSessionKey);
						response.addObject(vec);

					}
					else
					{
						response = new Envelope("FAIL");
						output.writeObject(response);
					}
				}
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
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();

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

				File file = new File(destFile);
			    try {


				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env);

					    env = (Envelope)input.readObject();

						while (env.getMessage().compareTo("CHUNK")==0) {
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env);
								env = (Envelope)input.readObject();
						}
						fos.close();

					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
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
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 e = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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
			UserToken token) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);


			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }


			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					message.addObject(buf);
					message.addObject(new Integer(n));

					output.writeObject(message);


					env = (Envelope)input.readObject();


			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
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

}
