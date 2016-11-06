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

public class GroupClient extends Client implements GroupClientInterface
{
	//AES key defined for the connection session with the Group Server
	//Not even sure if it will work this way but it's worth a shot
	private Key sessionKey;

	 public UserToken getToken(String username, KeyPair userKey)
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
      PublicKey sPubKey = null;
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
						byte[] aesTok = (byte[])response.getObjContents().get(2);
						byte[] ivBytes = (byte[])response.getObjContents().get(3);
						// Create IV from ivBytes
						IvParameterSpec IV = new IvParameterSpec(ivBytes);
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
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
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
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
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

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
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
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
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
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);

			 response = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				List<String> ret = new ArrayList<String>((List<String>)response.getObjContents().get(0));
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
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
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
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
		BigInteger dcBI = new BigInteger(byteText);
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


	 //TODO implement encryption and decryption for message passing
	 //Would be possibly easier to make 4 methods, two for enc/dec in AES and two for enc/dec in RSA

	//OPTIONAL from Phase 2: Create addOwnerToGroup

	//OPTIONAL from Phase 2: Create deleteOwnerFromGroup
}
