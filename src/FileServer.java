/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import org.bouncycastle.*;
import java.security.*;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	private KeyPair servPair;

	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}

	public void start() {
		//set provider to bouncycastle
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		String fileFile = "FileList.bin";
		//RSA Keypair for the file server
		String keyFile = "FileKeys.bin";

		ObjectInputStream fileStream;
		ObjectInputStream keyStream; //input stream for RSA keypair

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		try
		{
			FileInputStream kfis = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(kfis);
			servPair = (KeyPair)keyStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("RSA Key pair does not exist, creating servPair...");
			try
			{
				KeyPairGenerator sKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
				sKeyGen.initialize(2048);
				servPair = sKeyGen.generateKeyPair();

				//writes RSA keypair to disk
				ObjectOutputStream keyOutStream = new ObjectOutputStream(new FileOutputStream(keyFile));
				keyOutStream.writeObject(servPair);
				keyOutStream.close();
				
				//calculate SHA-256 hash
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] keyBytes = servPair.getPublic().getEncoded();
				md.update(keyBytes);
				byte[] digest = md.digest();
				System.out.println("SHA-256 Hash of public key is:");
				for(int i = 0; i < digest.length; i++)
				{
					System.out.print(digest[i]);
				}
				System.out.println();
			}
			catch(NoSuchAlgorithmException BCErr)
			{
				System.err.println("Error: " + BCErr.getMessage());
				BCErr.printStackTrace(System.err);
				System.exit(-1);
			}
			catch(NoSuchProviderException BCErr)
			{
				System.err.println("Error: " + BCErr.getMessage());
				BCErr.printStackTrace(System.err);
				System.exit(-1);
			}
			catch(FileNotFoundException ee)
			{
				System.err.println(ee.getMessage());
				ee.printStackTrace(System.err);
				System.exit(-1);
			}
			catch(IOException ee)
			{
				System.err.println(ee.getMessage());
				ee.printStackTrace(System.err);
				System.exit(-1);
			}
		}
		catch (IOException e)
		{
			System.err.println(e.getMessage());
			e.printStackTrace(System.err);
			System.exit(-1);
		}
		catch (ClassNotFoundException e)
		{
			System.err.println(e.getMessage());
			e.printStackTrace(System.err);
			System.exit(-1);
		}

		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");
		 }

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(sock, this);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	public Key getPublicKey() {
		//Function to get the public keyt
		Key servPubKey = servPair.getPublic();
		return servPubKey;
	}

	public Key getPrivateKey() {
		Key servPrivKey = servPair.getPrivate();
		return servPrivKey;
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
