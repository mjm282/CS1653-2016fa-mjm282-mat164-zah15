/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.*;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.math.BigInteger;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}

	public void run()
	{
		//The shared AES key for the current session
		Key sessionKey = null;

		boolean proceed = true;

		IvParameterSpec IV = null;

		int checkCount = -1;
		int counterGC = -1;
		int counterGS = -1;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Serializer mySerializer = new Serializer();
			ArrayList<Object> macList = null;
			counterGS = 0;

			do
			{
				Envelope message = (Envelope)input.readObject();
				Envelope response = null;
				if(message.getMessage().compareTo("DISCONNECT") != 0 && sessionKey != null)
				{
					checkCount = decryptAEScounter(message.getCounter(), sessionKey, IV);
					macList = new ArrayList<Object>(message.getObjContents().subList(0, message.getObjContents().size()-1));
					if(counterGC >= checkCount)
					{
						System.out.println("Replay/Reorder detected: terminating connection");
						socket.close();
						proceed = false;
					}
					else if(message.getHMAC().compareTo(generateHMAC(macList, sessionKey))!=0)
					{
						System.out.println("Modification detected: terminating connection");
						socket.close();
						proceed = false;
					}
					else
					{
						counterGC = checkCount;
					}
				}

				System.out.println("Request received: " + message.getMessage());


				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					String fServer = (String)message.getObjContents().get(1); //Get the File Server Name
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						response.addObject(counterGS);
						output.writeObject(response);
						counterGS++;
					}
					else
					{
						//TODO: client-server authentication
						//Look up the user in UserList by their username, get their public key
						//Generate a random BigInteger challenge
						//Encrypt it with their public key, send it to the user
						//Wait for a response, verify the challenge response is correct
						//Decrypt the second challenge sent from the user, send it back encrypted with their public key
						//Generate an AES secret key and set the value of sessionKey as such
						//In addition to the above, just simply do exactly what's below for creating tokens
							//(I'll sort out timestamping within Token.java)
						//Sign the token and encrypt it with sessionKey, send that
						//We're also sending a hash right? also do that.

						// Start of Turley Doing things
						// Look up user's public key
						PublicKey userKey = my_gs.userList.getUserKey(username);
						if (userKey == null)
						{
							response = new Envelope("FAIL");
							response.addObject(counterGS);
							output.writeObject(response);
							counterGS++;
							System.out.println(username + "'s Key Does Not Exist");
							return;
						}
						checkCount = decryptCounterRSA((byte[])message.getObjContents().get(2), my_gs.getPrivateKey());
						if(counterGC >= checkCount)
						{
							System.out.println("Replay/Reorder detected: terminating connection");
							socket.close();
							proceed = false;
						}
						else
						{
							counterGC = checkCount;
						}
						// Create BigInteger challenge
						// We need it to be random
						Random chalRand = new Random();
						// Now create the BigInteger
						BigInteger chal = new BigInteger(256, chalRand);
						// Now Encrypt that ish
						byte[] cipherBI = encryptChalRSA(chal, userKey);
						// And send that Encrypted ish
						response = new Envelope("OK");
						response.addObject(cipherBI); // 0
						response.addObject(encryptCounterRSA(counterGS, userKey));
						output.writeObject(response);
						counterGS++;
						// Wait for message
						message = (Envelope)input.readObject();
						checkCount = decryptCounterRSA((byte[])message.getObjContents().get(2), my_gs.getPrivateKey());
						if(counterGC >= checkCount)
						{
							System.out.println("Replay/Reorder detected: terminating connection");
							socket.close();
							proceed = false;
						}
						else
						{
							counterGC = checkCount;
						}
						// Read in the responce ... I think :/
						BigInteger c1 = (BigInteger)message.getObjContents().get(0);
						if (c1.equals(chal))
						{
							System.out.println("C1 Verified");
							// Checking token exist before doing all the challange work
							UserToken yourToken = createToken(username, fServer);
							if(yourToken != null)
							{
								System.out.println("Found Token");
								// Get CiperText
								byte[] ciph2 = (byte[])message.getObjContents().get(1);
								// Decrypt CipherText
								BigInteger c2 = decryptBIRSA(ciph2, my_gs.getPrivateKey());
								System.out.println("C2: " + c2.toString());
								// Switch to User's public key
								//byte[] cipherBI2 = encryptChalRSA(c2, userKey);
								// Need to generate that AES key!
								sessionKey = genSessionKey();
								System.out.println("Session Key" + sessionKey.toString());
								// Need to encrypt the session key
								byte[] rsaSessionKey = encryptAESKeyRSA(sessionKey, userKey); // Add to message
								System.out.println("RSA Encrypted Session Key");
								// Serialize the Token
								Serializer byteTok = new Serializer();
								byte[] serTok = byteTok.serialize(yourToken);
								System.out.println("Serilized Token");
								// Now we need to encrypt those byte[](s)
								// Make an IV
								SecureRandom ivRand = new SecureRandom();
								byte[] ivBytes = new byte[16];
								ivRand.nextBytes(ivBytes);
								IV = new IvParameterSpec(ivBytes);
								System.out.println(IV);
								System.out.println("Created IV");
								// And encrypt the Token!
								byte[] aesTok = encryptAES(serTok, sessionKey, IV);
								System.out.println("Encrypted Token");
								// Now we just have to send it all back!

								//Respond to the client. On error, the client will receive a null token
								// Restructure with challannge
								response = new Envelope("OK");
								// Add challenge
								response.addObject(c2); //0
								System.out.println("Added C2");
								// Add AES sessionKey (encrypted)
								response.addObject(rsaSessionKey);  //1
								System.out.println("Added RSA Encrypted Session Key");
								// Add encrypted token
								response.addObject(aesTok); //2
								System.out.println("Added AES Encrypted Token");
								// And the IV would help in decryption
								response.addObject(ivBytes); //3
								System.out.println("Added ivBytes");
								// Apend counter (encrypted with sessionKey) to end of response
								response.addObject(encryptAEScounter(counterGS, sessionKey, IV)); //4
								System.out.println("Added counter value");
								// Send back response
								output.writeObject(response);
								counterGS++;
								System.out.println("Sent Back Response");
							}
							else
							{
								response = new Envelope("FAIL");
								response.addObject(encryptCounterRSA(counterGS, userKey));
								output.writeObject(response);
								counterGS++;
							}
						}
						else
						{
							// The challenge does not match ... sad day
							response = new Envelope("FAIL");
							response.addObject(encryptCounterRSA(counterGS, userKey));
							output.writeObject(response);
							counterGS++;
						}
						// End of Turley doing things
					}
				}

				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								byte[] eUsername = (byte[])message.getObjContents().get(0); //Extract the username
								byte[] eToken = (byte[])message.getObjContents().get(1); //Extract the token

								String username = new String(decryptAES(eUsername, sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES(eToken, sessionKey, IV));
								System.out.println("Create User: " + username);

								if (yourToken.verifySignature(my_gs.getPublicKey()))
								{
								  System.out.println("Token Verified");
									if(createUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
								System.out.println("Del User: " + username);

								if (yourToken.verifySignature(my_gs.getPublicKey()))
								{
								  System.out.println("Token Verified");
									if(deleteUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
								System.out.println("Create Group: " + groupName);

								if (yourToken.verifySignature(my_gs.getPublicKey()))
								{
								  System.out.println("Token Verified");
									if(createGroup(groupName, yourToken))
									{
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
								System.out.println("Delete Group: " + groupName);

								if (yourToken.verifySignature(my_gs.getPublicKey()))
								{
								  System.out.println("Token Verified");
									if(deleteGroup(groupName, yourToken))
									{
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
								System.out.println("Group: " + groupName);

								if (yourToken.verifySignature(my_gs.getPublicKey()))
								{
								  System.out.println("Token Verified");
									List<String> memberList = listMembers(groupName, yourToken);
									if(memberList != null)
									{
										response = new Envelope("OK");
										response.addObject(encryptAES(mySerializer.serialize(memberList), sessionKey, IV));
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
									String groupName = new String(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
									UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(2), sessionKey, IV));

									System.out.println("Username: " + username);
									System.out.println("Group Name: " + groupName);

									if (yourToken.verifySignature(my_gs.getPublicKey()))
									{
									  System.out.println("Token Verified");
										if(addUserToGroup(username, groupName, yourToken))
										{
											response = new Envelope("OK");
										}
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
									String groupName = new String(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
									UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(2), sessionKey, IV));

									System.out.println("Username: " + username);
									System.out.println("Group Name: " + groupName);

									if (yourToken.verifySignature(my_gs.getPublicKey()))
									{
									  System.out.println("Token Verified");
										if(removeUserFromGroup(username, groupName, yourToken))
										{
											response = new Envelope("OK");
										}
									}
								}
							}
						}
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else if(message.getMessage().equals("GETK"))
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else if(message.getObjContents().size() == 5)
					{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
									//int keyNum = (Integer)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));
									byte[] numBytes = decryptAES((byte[]) message.getObjContents().get(1), sessionKey, IV);
									int keyNum = ((numBytes[0] & 0xFF) << 24) | ((numBytes[1] & 0xFF) << 16) | ((numBytes[2] & 0xFF) << 8) | (numBytes[3] & 0xFF);
									UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(2), sessionKey, IV));

									if(yourToken.verifySignature(my_gs.getPublicKey()))
									{
										System.out.println("Token Verified");
										Key groupKey = getGroupKey(groupName, keyNum, yourToken);
										if(groupKey != null)
										{
											response = new Envelope("OK");
											response.addObject(encryptGroupKey(groupKey, sessionKey, IV));
										}
									}
								}
							}
						}
					}
					else if(message.getObjContents().size() == 4)
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupName = new String(decryptAES((byte[])message.getObjContents().get(0), sessionKey, IV));
								UserToken yourToken = (UserToken)mySerializer.deserialize(decryptAES((byte[])message.getObjContents().get(1), sessionKey, IV));

								if(yourToken.verifySignature(my_gs.getPublicKey()))
								{
									System.out.println("Token Verified");
									Key groupKey = getGroupKey(groupName, yourToken);
									if(groupKey != null)
									{
										response = new Envelope("OK");
										response.addObject(encryptGroupKey(groupKey, sessionKey, IV));
										response.addObject(my_gs.groupList.getNum(groupName));
									}
								}
							}
						}
					}
					else
					{
						response = new Envelope("FAIL");
					}
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					response.addObject(encryptAEScounter(counterGS, sessionKey, IV));
					response.addObject(generateHMAC(response.getObjContents(), sessionKey));
					output.writeObject(response);
					counterGS++;
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	//Method to create tokens
	private UserToken createToken(String username, String fServer)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), my_gs.getPrivateKey(), fServer);
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		//sets the provider, will need to generate keypair for the user to use with this server
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					//generates a keypair for the user and saves it to a file to be given to the user and kept on a flash drive/smartcard/whatever
					//assumes that the admin is trusted, gives this file to the user via OFFLINE means
					//current implementation will be crude and temporary maybe?
					String outPath = username + ".bin";
					try
					{
						KeyPairGenerator uKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
						uKeyGen.initialize(2048);
						KeyPair uKeyPair = uKeyGen.generateKeyPair();

						ObjectOutputStream keyOutStream = new ObjectOutputStream(new FileOutputStream(outPath));
						keyOutStream.writeObject(uKeyPair);

						my_gs.userList.addUser(username, uKeyPair.getPublic());
					}
					catch(Exception e)
					{
						System.err.println(e.getMessage());
						e.printStackTrace(System.err);
						return false;
					}
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//Removes user from groups they belong in
					for(int index = 0; index< deleteFromGroups.size(); index++)
					{
						removeUserFromGroup(username, deleteFromGroups.get(index), yourToken);
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, my_gs.getPrivateKey(), "127.0.0.1"));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to create a group
	private boolean createGroup(String groupName, UserToken yourToken)
	{
		//Assumed user doesn't need to be an admin to create groups
		//doesn't check the token for administrative rights
		String requester = yourToken.getSubject();

		//checks if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//checks to see if the group already exists
			if(my_gs.groupList.checkGroup(groupName))
			{
				return false; //group already exists
			}
			else
			{
				my_gs.groupList.addGroup(groupName); //creates the group

				//Adds owner to the group upon group creation for the time being
				//CREATE ADD/REMOVE OWNER METHODS IN GROUP CLIENT

				my_gs.groupList.addGroupOwner(groupName, requester); //sets creator as owner
				my_gs.groupList.addGroupUser(groupName, requester); //sets creator as a group member
				my_gs.userList.addGroup(requester, groupName);
				my_gs.userList.addOwnership(requester, groupName);
				return true;
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean deleteGroup(String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//checks to see if the user exists
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//if the user is an admin that overrules ownership
			//makes sure the user is a group owner OR an administrator
			if(temp.contains("ADMIN") || my_gs.groupList.checkOwner(groupName, requester))
			{
				//checks if the group exists
				if(my_gs.groupList.checkGroup(groupName))
				{
					//will need to remove this group from all users' group list
					ArrayList<String> deleteFromUsers = new ArrayList<String>();

					//list all users that were in the group for deletion
					for(int i = 0; i < my_gs.groupList.getGroupMembers(groupName).size(); i++)
					{
						deleteFromUsers.add(my_gs.groupList.getGroupMembers(groupName).get(i));
					}

					//will also need to remove this group from all owners' ownership
					ArrayList<String> deleteFromOwners = new ArrayList<String>();

					//lists all users that were owners for deletion
					for(int i = 0; i < my_gs.groupList.getGroupOwners(groupName).size(); i++)
					{
						deleteFromOwners.add(my_gs.groupList.getGroupOwners(groupName).get(i));
					}

					//removes this group from all users
					for(int i = 0; i < deleteFromUsers.size(); i++)
					{
						my_gs.userList.removeGroup(deleteFromUsers.get(i), groupName);
					}

					//removes this group from all owners
					for(int i = 0; i < deleteFromOwners.size(); i++)
					{
						my_gs.userList.removeOwnership(deleteFromOwners.get(i), groupName);
					}

					//finally removes the group from the list
					my_gs.groupList.deleteGroup(groupName);

					return true;
				}
				else
				{
					return false; //group does not exist
				}
			}
			else
			{
				return false; //user can not delete this group
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//returns a list of group members
	private List<String> listMembers(String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//does requester exist
		if(my_gs.userList.checkUser(requester))
		{
			//does group exist
			if(my_gs.groupList.checkGroup(groupName))
			{
				//user must be admin or a member of the group to view its members
				ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
				if(temp.contains("ADMIN") || my_gs.groupList.checkMember(groupName, requester))
				{
					ArrayList<String> ret = new ArrayList<String>();
					ret = my_gs.groupList.getGroupMembers(groupName);
					return ret;
				}
				else
				{
					return null; //user can't view the group's members
				}
			}
			else
			{
				return null; //group does not exist
			}
		}
		else
		{
			return null; //requester doesn't exist
		}
	}

	private boolean addUserToGroup(String username, String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);

			//checks if you're an admin or an owner
			if(temp.contains("ADMIN") || my_gs.groupList.checkOwner(groupName, requester))
			{
				//does the user to be added exist
				if(my_gs.userList.checkUser(username))
				{

					if(my_gs.groupList.checkGroup(groupName))
					{
						//is the user already in the group?
						if(my_gs.groupList.checkMember(groupName, username))
						{
							return false; //user already in the group
						}
						else
						{
							//adds user to groupList
							my_gs.groupList.addGroupUser(groupName, username);
							//adds group to user's list of groups
							my_gs.userList.addGroup(username, groupName);

							return true;
						}
					}
					else
					{
						return false; //group does not exist
					}
				}
				else
				{
					return false; //user does not exist
				}
			}
			else
			{
				return false; //no permission to add a user
			}
		}
		else
		{
			return false; //requester doesn't exist
		}
	}

	private boolean removeUserFromGroup(String username, String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		if(my_gs.userList.checkUser(requester))
		{
			//checks admin/ownership
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			if(temp.contains("ADMIN") || my_gs.groupList.checkOwner(groupName, requester))
			{
				//does the group exist
				if(my_gs.groupList.checkGroup(groupName))
				{
					//is the user even in the group?
					if(my_gs.groupList.checkMember(groupName, username))
					{
						//remove from grouplist
						my_gs.groupList.removeGroupUser(groupName, username);
						//remove from user's list of groups
						my_gs.userList.removeGroup(username, groupName);

						return true;
					}
					else
					{
						return false; //user isn't a member
					}
				}
				else
				{
					return false; //group does not exist
				}
			}
			else
			{
				return false; //no permission to delete users
			}
		}
		else
		{
			return false; //requester doesn't exist
		}
	}

	private Key getGroupKey (String groupName, int keyNum, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//does the user exist
		if(my_gs.userList.checkUser(requester))
		{
			//does the group exist
			if(my_gs.groupList.checkGroup(groupName))
			{
				//is the user in the group
				if(my_gs.groupList.checkMember(groupName, requester))
				{
					return  my_gs.groupList.getKey(groupName, keyNum);
				}
				else
				{
					return null; //user not in group
				}
			}
			else
			{
				return null; //group doesn't exist
			}
		}
		else
		{
			return null; //user doesn't exist
		}
	}

	private Key getGroupKey (String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//does the user exist
		if(my_gs.userList.checkUser(requester))
		{
			//does the group exist
			//if(my_gs.groupList.checkGroup(groupName))
			//{
				//is the user in the group
				if(my_gs.groupList.checkMember(groupName, requester))
				{
					return  my_gs.groupList.getKey(groupName);
				}
				else
				{
					//System.out.println("not in group");
					return null; //user not in group
				}
			//}
			//else
			//{
			//	return null; //group doesn't exist
			//}
		}
		else
		{
			//System.out.println("user DNE");
			return null; //user doesn't exist
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

  public static byte[] encryptGroupKey(Key gKey, Key sKey, IvParameterSpec IV) throws Exception
  {
	  Cipher sCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
	  sCipher.init(Cipher.ENCRYPT_MODE, sKey, IV);
	  byte[] byteKey = sCipher.doFinal(gKey.getEncoded());
	  return byteKey;
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

	public static byte[] encryptAEScounter(int counter, Key AESkey, IvParameterSpec IV) throws Exception
	{
		BigInteger temp = new BigInteger(Integer.toString(counter));
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aesCipher.init(Cipher.ENCRYPT_MODE, AESkey, IV);
		byte[] byteCipherText = aesCipher.doFinal(temp.toByteArray());
		return byteCipherText;
	}

	public static int decryptAEScounter(byte[] cipherText, Key AESkey, IvParameterSpec IV) throws Exception
	{
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aesCipher.init(Cipher.DECRYPT_MODE, AESkey, IV);
		byte[] byteText = aesCipher.doFinal(cipherText);
		BigInteger counter = new BigInteger(1, byteText);
		return counter.intValue();
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
