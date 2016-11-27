/* Implements the GroupClient Interface */
import java.util.*;
import java.io.*;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.*;
import java.security.*;
import java.math.BigInteger;
import org.bouncycastle.*;
import java.nio.ByteBuffer; //serializer was throwing errors to I decided to try a ByteBuffer

public class GroupClient extends Client implements GroupClientInterface
{
	//AES key defined for the connection session with the Group Server
	//Not even sure if it will work this way but it's worth a shot
	private Key sessionKey;
	private IvParameterSpec IV = null;
	private byte[] aesTok = null;
	private PublicKey sPubKey = null;

	 public UserToken getToken(String username, KeyPair userKey, String fServer)
	 {
		// Set security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		try
		{
			//TODO: Client-server authentication
			//send "GET" message with username
			//wait for a response from the server
			//decrypt challenge with private key
			//send message with decrypted challenge, re-encrypted with server public key AND a new generated challenge, also encrypted with server public key
			//check outcome of challenge response, if it's valid then also set sessionKey to recieved AES key
			//Were we doing some hash check here as well? Like checking a fingerpring of the token? if so do that as well
			//return the signed, encrypted, token

			//assume that we know the server's public key this whole time and implement some way to do so in our program that is somewhat secure

			UserToken token = null;
			Envelope message = null, response = null;

			// Client Keys
			Key cPrivKey = userKey.getPrivate();
			Key cPubKey  = userKey.getPublic();


			// Servers public key
      //gets the server's public key
      //PublicKey sPubKey = null;
      try
      {
        ObjectInputStream keyStream;
        FileInputStream fis = new FileInputStream("GroupPub.bin");
        keyStream = new ObjectInputStream(fis);

        sPubKey = (PublicKey)keyStream.readObject();
      }
      catch(FileNotFoundException e)
      {
        System.err.println("Make sure you have the file GroupPub.bin");
        System.exit(-1);
      }
      catch(IOException e)
      {
        System.out.println("Error reading from GroupPub.bin");
        System.exit(-1);
      }
      catch(ClassNotFoundException e)
      {
        System.out.println("Error reading from GroupPub.bin");
        System.exit(-1);
      }

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(fServer); // Add File Server address string so it can be added to the token
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			// Turley doing things
			ArrayList<Object> temp = null;
			if(response.getMessage().equals("OK"))
			{
				temp = response.getObjContents();
				// Get encrypted cipher
				byte[] ciph1 = (byte[])temp.get(0);
				// Decrypt cipher
				BigInteger C1 = decryptBIRSA(ciph1, cPrivKey); // Add to message
				// Create a C2
				// We need it to be random
				Random chalRand = new Random();
				// Now create the BigInteger
				BigInteger C2 = new BigInteger(256, chalRand);
				byte[] ciph2 = encryptChalRSA(C2, sPubKey); // Add to message
				// And lets send this ish on back to the user
				message = new Envelope("OK");
				message.addObject(C1); // 0
				message.addObject(ciph2); // 1
				output.writeObject(message); // Write it out
				// Wait for respnce
				response = (Envelope)input.readObject();
				if(response.getMessage().equals("OK"))
				{
					BigInteger rC2 = (BigInteger)response.getObjContents().get(0);
					if (C2.equals(rC2))
					{
						byte[] rsaSessionKey = (byte[])response.getObjContents().get(1);
						aesTok = (byte[])response.getObjContents().get(2);
						byte[] ivBytes = (byte[])response.getObjContents().get(3);
						// Create IV from ivBytes
						IV = new IvParameterSpec(ivBytes);
						// And we have a session key!
						sessionKey = decryptAESKeyRSA(rsaSessionKey, cPrivKey);
						// Now retrive the token
						byte[] serTok = decryptAES(aesTok, sessionKey, IV);
						// And Deserilize it
						Serializer mySerializer = new Serializer();
						token = (UserToken)mySerializer.deserialize(serTok);
						return token;
					}
				}
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

	 public boolean createUser(String username, UserToken token)
	 {
		 Serializer msgSer = new Serializer();
		 try
			{
				Envelope message = null, response = null, eMesg =null;
				byte[] byteMsg, eByteMsg;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(encryptAES(username.getBytes(), sessionKey, IV)); //Add user name string
				message.addObject(aesTok); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(encryptAES(username.getBytes(), sessionKey, IV)); //Add user name
				message.addObject(aesTok);  //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public PublicKey getGSkey() {
		 return sPubKey;
	 }

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(encryptAES(groupname.getBytes(), sessionKey, IV)); //Add the group name string
				message.addObject(aesTok); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(encryptAES(groupname.getBytes(), sessionKey, IV)); //Add the group name string
				message.addObject(aesTok); //Add the requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 Serializer mySerializer = new Serializer();
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(encryptAES(group.getBytes(), sessionKey, IV)); //Add the group name string
			 message.addObject(aesTok); //Add the requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				 // Not needed
				// List<String> ret = new ArrayList<String>((List<String>)response.getObjContents().get(0));
				// Decrypt and return
				// String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
				return (List<String>)mySerializer.deserialize(decryptAES((byte[])response.getObjContents().get(0), sessionKey, IV));
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

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(encryptAES(username.getBytes(), sessionKey, IV)); //Add user name string
				message.addObject(encryptAES(groupname.getBytes(), sessionKey, IV)); //Add group name string
				message.addObject(aesTok); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(encryptAES(username.getBytes(), sessionKey, IV)); //Add user name string
				message.addObject(encryptAES(groupname.getBytes(), sessionKey, IV)); //Add group name string
				message.addObject(aesTok); //Add requester's token
				output.writeObject(message);

				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 
	 //group key functions (mjm282)
	 
	 //needs to be able to get the group key from the server
	 //sends the group name, the key number the file is encrypted with (from the beginning of the file), and the user's token
	 public Key getGroupKey(String groupName, int keyNum, UserToken token)
	 {
		Serializer ser = new Serializer();
		try
		{
			Envelope message = null, response = null;
			 
			message = new Envelope("GETK");
			message.addObject(encryptAES(groupName.getBytes(), sessionKey, IV)); //Add user name string
			message.addObject(encryptAES((byte[])ser.serialize(keyNum), sessionKey, IV)); //Add group name string
			message.addObject(aesTok);
			
			output.writeObject(message);
			
			response = (Envelope) input.readObject();
			
			if(response.getMessage().equals("OK"))
			{
				Key retKey = new SecretKeySpec((byte[])ser.deserialize(decryptAES((byte[])response.getObjContents().get(0), sessionKey, IV)), "AES");
				return retKey;
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
	 
	 //if the client is uploading it will use the most recent key, so no keyNum will be passed in
	 public ArrayList<Object> getGroupKey(String groupName, UserToken token)
	 {
		 Serializer ser = new Serializer();
		try
		{
			Envelope message = null, response = null;
			 
			message = new Envelope("GETK");
			message.addObject(encryptAES(groupName.getBytes(), sessionKey, IV)); //Add user name string
			message.addObject(aesTok);
			
			output.writeObject(message);
			
			response = (Envelope) input.readObject();
			
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> ret = new ArrayList<Object>();
				Key gKey = new SecretKeySpec(decryptAES((byte[])response.getObjContents().get(0), sessionKey, IV), "AES");
				System.out.println("group key = " + gKey.toString());
				ret.add(gKey);
				ret.add(response.getObjContents().get(1));
				System.out.println(ret);
				return ret;
//				Key retKey = new SecretKeySpec((byte[])ser.deserialize(decryptAES((byte[])response.getObjContents().get(0), sessionKey, IV)), "AES");
//				return retKey;
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
	 
	 //does everything needed to get a group key, parse out key number and IV, and decrypt a file
	 //doing this in GroupClient because it's slightly more convenient
	 public boolean downloadDec(String dFile, UserToken token)
	 {
		IvParameterSpec fileIV = null;
		Key groupKey = null;
		Integer keyNum;
		String group = null;
		byte[] startBytes = new byte[120];
		byte[] ivBytes = new byte[16];
		byte[] numBytes = new byte[4];
		byte[] groupBytes = new byte[100];
		
		Serializer ser = new Serializer();
		
		try
		{
		
		String encFile = dFile + ".enc";
		File inFile = new File(encFile);
		File outFile = new File(dFile);
		outFile.createNewFile();
		
		//creates a file input stream and reads the first chunk from the file
		//also creates a file output stream to save the decrypted file contents
		FileInputStream fis = new FileInputStream(inFile);
		FileOutputStream fos = new FileOutputStream(outFile);
		
		boolean firstChunk = true;
		
		do{
			//reads a full chunk into memory
			byte[] buf = new byte[4096];
			int in = fis.read(buf);
		
			//if this is the first chunk we need to get the key number, group, and IV out of the file
			if(firstChunk)
			{
				firstChunk = false;
				for(int i = 0; i < 120; i++)
				{
					if(i < 4)
					{
						numBytes[i] = buf[i];
						//System.out.println(numBytes[i]);
					}
					else if(i < 20)
					{
						ivBytes[i-4] = buf[i];
						//System.out.println(ivBytes[i-4]);
					}
					else
					{
						groupBytes[i-20] = buf[i];
						//System.out.println(groupBytes[i-20]);
					}
				}
				
				for(int i = 0; i < 4; i++)
				{
					System.out.print(numBytes[i]);
				}
				System.out.println();
				
				
				keyNum = ByteBuffer.wrap(numBytes).getInt();
				
				System.out.println(keyNum);
				
				for(int i = 0; i < 16; i++)
				{
					
				}
			
				
				
				fileIV = new IvParameterSpec(ivBytes);
				groupKey = getGroupKey("ADMIN", 0, token);
				fos.write((byte[]) decryptAES(buf, groupKey, fileIV), 120, in - 120);
			
			}
			else
			{
				fos.write((byte[]) decryptAES(buf, groupKey, fileIV), 0, in);
			}
		}while(fis.available() > 0);
		
		inFile.delete();
		
		fos.close();
		fis.close();
		
		}catch(Exception e){
			e.printStackTrace();
			return false;
		}
		
		return true;
	 }
	 
	 
	 // RSA Functions (Turley)
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

	
	
	 //TODO implement encryption and decryption for message passing
	 //Would be possibly easier to make 4 methods, two for enc/dec in AES and two for enc/dec in RSA

	//OPTIONAL from Phase 2: Create addOwnerToGroup

	//OPTIONAL from Phase 2: Create deleteOwnerFromGroup
}
