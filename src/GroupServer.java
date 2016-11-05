/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * PHASE 3 TODO: Add state saving regarding the server's keypair as well as adding public keys to each user's UserList entry
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import org.bouncycastle.*;


public class GroupServer extends Server
{

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	private KeyPair servPair;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	ObjectOutputStream userOutStream;
	ObjectOutputStream groupOutStream;

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		//sets security provider to bouncycastle
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		//kind of insecure, but assuming the server is trustworthy this is fine right now
		String keyFile = "ServerKeys.bin"; //Stores the server's keypair

		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream keyStream; //input stream for RSA keypair
		String username;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//open keyFile to get server's keypair
		try
		{
			FileInputStream fis = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(fis);
			servPair = (KeyPair)keyStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupServer RSA Key pair does not exist, creating servPair...");
			try
			{
				KeyPairGenerator sKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
				sKeyGen.initialize(2048);
				servPair = sKeyGen.generateKeyPair();

				try
				{
					//writes the keypair for storage
					ObjectOutputStream keyOutStream = new ObjectOutputStream(new FileOutputStream(keyFile));
					keyOutStream.writeObject(servPair);
					keyOutStream.close();
				}
				catch(FileNotFoundException ee)
				{
					System.err.println(ee.getMessage());
					ee.printStackTrace(System.err);
				}
				catch(IOException ee)
				{
					System.err.println(ee.getMessage());
					ee.printStackTrace(System.err);
				}
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
		}
		catch(IOException e)
		{
			System.out.println("Error reading from ServerKeys file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from ServerKeys file");
			System.exit(-1);
		}


		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			username = console.next();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			groupList = new GroupList();

			//generates the admin's keypair (this will likely be temporary) and saves it to a separate file for safekeeping, adds the public key to the admin's userList entry
			try
			{
				KeyPairGenerator adminKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
				adminKeyGen.initialize(2048);
				KeyPair adminPair = adminKeyGen.generateKeyPair();
				userList.addUser(username, adminPair.getPublic());

				//store's admin's keypair to disk
				String admPath = username + ".bin";
				//writes the keypair for storage
				ObjectOutputStream keyOutStream = new ObjectOutputStream(new FileOutputStream(admPath));
				keyOutStream.writeObject(servPair);
				keyOutStream.close();
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
			catch(FileNotFoundException BCErr)
			{
				System.err.println("Error: " + BCErr.getMessage());
				BCErr.printStackTrace(System.err);
				System.exit(-1);
			}
			catch(IOException BCErr)
			{
				System.err.println("Error: " + BCErr.getMessage());
				BCErr.printStackTrace(System.err);
				System.exit(-1);
			}


			groupList.addGroup("ADMIN");
			groupList.addGroupUser("ADMIN", username);
			groupList.addGroupOwner("ADMIN", username);

			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			try
			{
				groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
				groupOutStream.writeObject(this.groupList);
			}
			catch(Exception ee)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		//Open group file to get group list
		try
		{
			FileInputStream fis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis);
			groupList = (GroupList)groupStream.readObject();
			//runtime.gc();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupList File Does Not Exist. Creating GroupList");
			System.out.println("No groups currently exist. Group \"ADMIN\" will be created.");
			System.out.println("Your account will be the administrator.");
			System.out.print("Enter your username: ");
			username = console.next();

			//Create a new group list, add current user to the ADMIN group. They now own the ADMIN group.
			//groupList = new GroupList();
			//CHECK GROUPLIST IMPLEMENTATION

			groupList.addGroup("ADMIN");
			groupList.addGroupUser("ADMIN", username);
			groupList.addGroupOwner("ADMIN", username);

			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

	public Key getPublicKey() {
		// Function to get the public key
		Key servPubKey = servPair.getPublic();
		return servPubKey;
	}

	public Key getPrivateKey() {
		Key servPrivateKey = servPair.getPrivate();
		return servPrivateKey;

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream userOutStream;
		ObjectOutputStream groupOutStream;
		try
		{
			userOutStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			userOutStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try
		{
			groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			groupOutStream.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream userOutStream;
				ObjectOutputStream groupOutStream;
				try
				{
					userOutStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					userOutStream.writeObject(my_gs.userList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try
				{
					groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					groupOutStream.writeObject(my_gs.groupList);
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
