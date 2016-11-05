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
		Key sessionKey;
		UserToken uToken;
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
			resonse = (Envelope)input.readObject();
			privKey = my_fs.getPrivateKey();
			if(response.getMessage.compareTo("OK")==0)
			{
				byte[] chal = (byte[])response.getObjContents().get(0);
				Cipher rsaCipher = Cipher.getInstance("RSA", "BC");
				rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
				byte[] byteText = rsaCipher.doFinal(chal);
				BigInteger plainChal = new BigInteger(byteText);

				//Send back plaintext challenge
				message - new Envelope("OK")
				message.addObject(plainChal);
				output.writeObject(message);
			}
			else
			{
				message = new Envelope("FAIL");
				output.writeObject(message);
			}

			//Decrypt toekn and AES key
			response = (Envelope)input.readObject();
			if(response.getMessage().compareTo("OK")==0)
			{
				byte[] aesToken = (byte[])reponse.getObjContents().get(0);
				byte[] rsaSessionKey = (byte[])response.getObjContents().get(1);
				IvParameterSpec vec = (IvParameterSpec)response.getObjContents().get(2);

				//Decrypt sessionKey
				rsaCipher = Cipher.getInstance("RSA", "BC");
				rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
				sessionKey = (Key)rsaCipher.doFinal(rsaSessionKey);

				Cipher aesCipher = Cipher.getInstance("AES", "BC");
				aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, vec);
				uToken = (UserToken)aesCipher.doFinal(aesToken);

			}


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
							UserToken workingToken = (UserToken)e.getObjContents().get(0);
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
							response.addObject(userFiles); // Append the file list the responce
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
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

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
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
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

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
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


								e.addObject(buf);
								e.addObject(new Integer(n));

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

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
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

}
