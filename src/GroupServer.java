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
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherOutputStream;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;


public class GroupServer extends Server
{

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	private KeyPair servPair;
	public Key gKey;
	public IvParameterSpec IV;
	public Key adminKey;
	public byte[] ivBytes;

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
		String keyFile = "GroupPair.bin"; //Stores the server's keypair
		String pubFile = "GroupPub.bin"; //stores just the server's public key

		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream keyStream; //input stream for RSA keypair
		String username;
		
		String setpass1 = null;
		String setpass2 = null;
		String password = null;
		boolean match = false;

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

					keyOutStream = new ObjectOutputStream(new FileOutputStream(pubFile));
					keyOutStream.writeObject(servPair.getPublic());
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
				keyOutStream.writeObject(adminPair);
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

			//T8 Solution, prompt the administrator to set up a password for encrypting groupList before groupList is created and written to file
			System.out.println("Before we set up the GroupList file, please create a password for secure storage.");
			while(!match)
			{
				setpass1 = console.next();
				//eight character minimum length, not too big, not to small
				if(setpass1.length() >= 8) 
				{
					System.out.println("Please re-enter your password");
					setpass2 = console.next();
					if(setpass1.equals(setpass2)) 
					{
						match = true;
						password = setpass1;
					}
					else System.out.println("Passwords do not match!");					
				}
				else
				{
					System.out.println("Password is too short, needs to be at least 8 characters");
				}
			}
			
			try
			{
				// groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
				//groupOutStream.writeObject(this.groupList);
				
				Serializer glSer = new Serializer();
				
				adminKey = getAdminKey(password);	//gets the key to encrypt GroupList.bin's AES encryption key stored at the start of the file
				//having an AES encrypted AES key allows for password changing
				
				//generates an IV for GroupList.bin, will be stored at the beginning of the file
				SecureRandom ivRand = new SecureRandom();
				ivBytes = new byte[16];
				ivRand.nextBytes(ivBytes);
				IV = new IvParameterSpec(ivBytes);
				
				//generate the actual AES key to encrypt GroupList.bin
				gKey = genKey();
				
				Cipher outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				outCipher.init(Cipher.ENCRYPT_MODE, gKey, IV);
				
				FileOutputStream gfos = new FileOutputStream(groupFile);
				CipherOutputStream gcos = new CipherOutputStream(gfos, outCipher);
				
				//encrypts gKey and writes the encrypted key to file
				//going to use ECB because they key will be one block anyways and it saves some work having to store two IVs
				Cipher gCipher = Cipher.getInstance("AES", "BC");
				gCipher.init(Cipher.ENCRYPT_MODE, adminKey);
				byte[] gKeyEnc = gCipher.doFinal(gKey.getEncoded());
				
				FileOutputStream mfos = new FileOutputStream("GroupList.meta");
				
				mfos.write(gKeyEnc);
				mfos.write(ivBytes);
				
				byte[] GLBytes = glSer.serialize(this.groupList);
				
				gcos.write(GLBytes);
				gcos.flush();
				gcos.close();
				gfos.close();
				
				//having issues with size of GLBytes being smaller than the size of the .bin file written out, causing some trash bytes to be read in through the CipherInputStream, going to store the size of GLBytes
				byte[] amtWrit = new byte[4];
				amtWrit[0] = (byte) (GLBytes.length >> 24);
				amtWrit[1] = (byte) (GLBytes.length >> 16);
				amtWrit[2] = (byte) (GLBytes.length >> 8);
				amtWrit[3] = (byte) (GLBytes.length);
				mfos.write(amtWrit);
				mfos.flush();
				mfos.close();
				
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
			if(groupList == null)
			{
				System.out.println("Please enter password to decrypt and load GroupList.bin");
				password = console.next();
				adminKey = getAdminKey(password);
				Serializer gSer = new Serializer();
				byte[] gKeyBytes = new byte[32];
				ivBytes = new byte[16];
				byte[] intBytes = new byte [4];
				
				FileInputStream mfis = new FileInputStream("GroupList.meta");
				
				mfis.read(gKeyBytes);
				mfis.read(ivBytes);
				mfis.read(intBytes);
				mfis.close();
				
				int writInt = ((intBytes[0] & 0xFF) << 24) | ((intBytes[1] & 0xFF) << 16) | ((intBytes[2] & 0xFF) << 8) | (intBytes[3] & 0xFF);
				
				//creates a cipher and decrypts the AES key using adminKey
				Cipher keyCipher = Cipher.getInstance("AES", "BC");
				keyCipher.init(Cipher.DECRYPT_MODE, adminKey);
				byte[] gKeyDec = keyCipher.doFinal(gKeyBytes);
				gKey = new SecretKeySpec(gKeyDec, "AES");
				
				//recreates the IV from the .meta file bytes
				IV = new IvParameterSpec(ivBytes);
				
				Cipher inCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
				inCipher.init(Cipher.DECRYPT_MODE, gKey, IV);

				FileInputStream gfis = new FileInputStream(groupFile);
				CipherInputStream gcis = new CipherInputStream(gfis, inCipher);
				
				byte[] GLBuf = new byte[writInt];
				System.out.println(GLBuf.length);
				boolean firstPass = true;
				
				System.out.println("5");
				byte[] buf = new byte[4096];
				int in = 0;
				int prevIn = 0;
				while((in = gcis.read(buf)) > 0)
				{
					if(firstPass)
					{
						for(int i = 0; i < in; i++)
						{
							GLBuf[i] = buf[i];
						}
						prevIn = in;
						firstPass = false;
					}
					else
					{
						for(int i = prevIn; i < GLBuf.length; i++)
						{
							GLBuf[i] = buf[i-prevIn];
						}
						prevIn = in;
					}
				}
				
				groupList = (GroupList) gSer.deserialize(GLBuf);
//				FileInputStream fis = new FileInputStream(groupFile);
//				groupStream = new ObjectInputStream(fis);
//				groupList = (GroupList)groupStream.readObject();
				//runtime.gc();
			}
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
			e.printStackTrace();
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(Exception e)
		{
			e.printStackTrace();
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

	public PublicKey getPublicKey() {
		// Function to get the public key
		PublicKey servPubKey = servPair.getPublic();
		return servPubKey;
	}

	public PrivateKey getPrivateKey() {
		PrivateKey servPrivateKey = servPair.getPrivate();
		return servPrivateKey;

	}
	
	//Generates a key from entered password
	public Key getAdminKey(String pass) throws Exception
	{
		//generates a SHA-256 hash of the admin's password
		//uses that hash (the first 128 bits of it because in 6110 only 128 bits have been working) to generate an AES key
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(pass.getBytes());
		byte[] hashPass = md.digest();
		byte[] passKey = new byte[hashPass.length / 2];
		for(int i = 0; i < passKey.length; i++)
		{
			passKey[i] = hashPass[i];
		}
		
		Key adminKey = new SecretKeySpec(passKey, "AES"); //the AES key generated from the admin's password	
		return adminKey;
	}
	
	public Key genKey() throws Exception
	{
		KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
		generator.init(128);
		Key myAESkey = generator.generateKey();
		return myAESkey;
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
		// ObjectOutputStream groupOutStream;
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
			Serializer glSer = new Serializer();
			
			Cipher outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			outCipher.init(Cipher.ENCRYPT_MODE, my_gs.gKey, my_gs.IV);
		
			FileOutputStream gfos = new FileOutputStream("GroupList.bin");
			CipherOutputStream gcos = new CipherOutputStream(gfos, outCipher);
			
			//encrypts gKey and writes the encrypted key to file
			//going to use ECB because they key will be one block anyways and it saves some work having to store two IVs
			Cipher gCipher = Cipher.getInstance("AES", "BC");
			gCipher.init(Cipher.ENCRYPT_MODE, my_gs.adminKey);
			byte[] gKeyEnc = gCipher.doFinal(my_gs.gKey.getEncoded());
			
			FileOutputStream mfos = new FileOutputStream("GroupList.meta");
			
			mfos.write(gKeyEnc);
			mfos.write(my_gs.ivBytes);
			
			byte[] GLBytes = glSer.serialize(my_gs.groupList);
			
			gcos.write(GLBytes);
			gcos.flush();
			gcos.close();
			gfos.close();
			// groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			//groupOutStream.writeObject(my_gs.groupList);
			
			byte[] amtWrit = new byte[4];
			amtWrit[0] = (byte) (GLBytes.length >> 24);
			amtWrit[1] = (byte) (GLBytes.length >> 16);
			amtWrit[2] = (byte) (GLBytes.length >> 8);
			amtWrit[3] = (byte) (GLBytes.length);
			mfos.write(amtWrit);
			mfos.flush();
			mfos.close();
		
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
					Serializer glSer = new Serializer();
					
					Cipher outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
					outCipher.init(Cipher.ENCRYPT_MODE, my_gs.gKey, my_gs.IV);
				
					FileOutputStream gfos = new FileOutputStream("GroupList.bin");
					CipherOutputStream gcos = new CipherOutputStream(gfos, outCipher);
					
					//encrypts gKey and writes the encrypted key to file
					//going to use ECB because they key will be one block anyways and it saves some work having to store two IVs
					Cipher gCipher = Cipher.getInstance("AES", "BC");
					gCipher.init(Cipher.ENCRYPT_MODE, my_gs.adminKey);
					byte[] gKeyEnc = gCipher.doFinal(my_gs.gKey.getEncoded());
					
					FileOutputStream mfos = new FileOutputStream("GroupList.meta");
					
					mfos.write(gKeyEnc);
					mfos.write(my_gs.ivBytes);
					
					byte[] GLBytes = glSer.serialize(my_gs.groupList);
					
					gcos.write(GLBytes);
					gcos.flush();
					gcos.close();
					gfos.close();
					// groupOutStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					//groupOutStream.writeObject(my_gs.groupList);
					
					byte[] amtWrit = new byte[4];
					amtWrit[0] = (byte) (GLBytes.length >> 24);
					amtWrit[1] = (byte) (GLBytes.length >> 16);
					amtWrit[2] = (byte) (GLBytes.length >> 8);
					amtWrit[3] = (byte) (GLBytes.length);
					mfos.write(amtWrit);
					mfos.flush();
					mfos.close();
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