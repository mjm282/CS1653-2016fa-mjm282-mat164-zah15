/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

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
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
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
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println(response.getMessage());
					output.writeObject(response);
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
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					System.out.println(response.getMessage());
					output.writeObject(response);
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
								String groupName = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);
								
								if(createGroup(groupName, yourToken))
								{
									response = new Envelope("OK");
								}
							}
						}
					}
					
					System.out.println(response.getMessage());
					output.writeObject(response);
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
								String groupName = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);
								
								if(deleteGroup(groupName, yourToken))
								{
									response = new Envelope("OK");
								}
							}
						}
					}
					System.out.println(response.getMessage());
					output.writeObject(response);
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
								String groupName = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);
								
								if(listMembers(groupName, yourToken))
								{
									response = new Envelope("OK");
								}
							}
						}
					}
					System.out.println(response.getMessage());
					output.writeObject(response);
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
									String groupName = (String)message.getObjContents().get(0);
									String username = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									
									if(addUserToGroup(groupName, yourToken, username))
									{
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					System.out.println(response.getMessage());
					output.writeObject(response);
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
									String groupName = (String)message.getObjContents().get(0);
									String username = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									
									if(removeUserFromGroup(groupName, yourToken, username))
									{
										response = new Envelope("OK");
									}
		
								}
							}
						}
					}
					System.out.println(response.getMessage());
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					System.out.println(response.getMessage());
					output.writeObject(response);
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
	private UserToken createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
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
					my_gs.userList.addUser(username);
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
						removeUserFromGroup(deleteFromGroups.get(index), yourToken, username);
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
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
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
	
	//displays a printout of all of the members of a specific group
	private boolean listMembers(String groupName, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		if(my_gs.userList.checkUser(requester))
		{
			//user must be admin or a member of the group to view its members
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			if(temp.contains("ADMIN") || my_gs.groupList.checkMember(groupName, requester))
			{
				temp = my_gs.groupList.getGroupMembers(groupName);
				for(int i = 0; i < temp.size(); i++)
				{
					System.out.println(temp.get(i));
				}
				
				return true;
			}
			else
			{
				return false; //user can't view the group's members
			}
		}
		else
		{
			return false; //requester doesn't exist
		}
	}
	
	private boolean addUserToGroup(String groupName, UserToken yourToken, String username)
	{
		String requester = yourToken.getSubject();
		
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
		
			//checks if you're an admin or an owner
			if(temp.contains("ADMIN") || my_gs.groupList.checkOwner(groupName, requester))
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
				return false; //no permission to add a user
			}
		}
		else
		{
			return false; //requester doesn't exist
		}
	}
	
	private boolean removeUserFromGroup(String groupName, UserToken yourToken, String username)
	{
		String requester = yourToken.getSubject();
		
		if(my_gs.userList.checkUser(requester))
		{
			//checks admin/ownership
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			if(temp.contains("ADMIN") || my_gs.groupList.checkOwner(groupName, requester))
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
				return false; //no permission to delete users
			}
		}
		else
		{
			return false; //requester doesn't exist
		}
	}
}
