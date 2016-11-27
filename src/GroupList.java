import java.util.*;
import org.bouncycastle.*;
import java.security.*;
import javax.crypto.KeyGenerator;


public class GroupList implements java.io.Serializable
{
	
	//this group list is mostly going to be a straight up clone of UserList.java
	
	//uses a hashtable to store each group, mapped by their names
	//a group contains the list of users in its group and a list of owners in the group, both just ArrayList<String>
	private Hashtable<String, Group> gList = new Hashtable<String, Group>();
	
	//creates a new group and maps it into the hashtable
	//assumes that some check will be performed elsewhere as to whether or not the group already exists
	public synchronized void addGroup(String groupName)
	{
		Group newGroup = new Group();
		gList.put(groupName, newGroup);
	}
	
	//deletes a group from the hashtable
	public synchronized void deleteGroup(String groupName)
	{
		gList.remove(groupName);
	}
	
	//checks the existence of a group in the table
	//if it already exists, returns true, if not false
	public synchronized boolean checkGroup(String groupName)
	{
		System.out.println("groupList " + groupName);
		System.out.println(gList);
		if(gList.containsKey(groupName)) 
		{
			return true;
		}
		else 
		{
			return false;
		}
	}
	
	//checks if the user is a group owner
	public synchronized boolean checkOwner(String groupName, String username)
	{
		ArrayList<String> temp = gList.get(groupName).getOwners();
		if(temp.contains(username))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	
	//checks if the user is a group member
	public synchronized boolean checkMember(String groupName, String username)
	{
		if(checkGroup(groupName))
		{
			ArrayList<String> temp = gList.get(groupName).getUsers();
			if(temp.contains(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
	
	//Implementation of LMEMBERS message, returns a list of members in a specified group
	public synchronized ArrayList<String> getGroupMembers(String groupName)
	{
		return gList.get(groupName).getUsers();
	}
	
	//Not a required method, just figured listing owners would be useful
	public synchronized ArrayList<String> getGroupOwners(String groupName)
	{
		return gList.get(groupName).getOwners();
	}
	
	//implementation of AUSERTOGROUP
	public synchronized void addGroupUser(String groupName, String username)
	{
		gList.get(groupName).addUser(username);
	}
	
	//implementation of RUSERFROMGROUP
	public synchronized void removeGroupUser(String groupName, String username)
	{
		gList.get(groupName).removeUser(username);
	}
	
	//adding and removing owners isn't required in phase 2 but I felt it would be useful later
	
	public synchronized void addGroupOwner(String groupName, String username)
	{
		gList.get(groupName).addOwner(username);
	}
	
	//add handlers for attempting to remove the one and only group owner later
	//not super neccesary as of phase 2
	public synchronized void removeGroupOwner(String groupName, String username)
	{
		gList.get(groupName).removeOwner(username);
	}
	
	public synchronized Key getKey(String groupName, int keyNum)
	{
		return gList.get(groupName).getKey(keyNum);
	}
	
	public synchronized Key getKey(String groupName)
	{
		return gList.get(groupName).getKey();
	}
	
	public synchronized int getNum(String groupName)
	{
		return gList.get(groupName).getNum();
	}
	
	/* group datatype
	 * contains the list of users that are in a specific group
	 * also contains a list of the owners of that group
	 * can add or remove owners and users to/from individual groups
	 */
	class Group implements java.io.Serializable
	{
		private ArrayList<String> users; //the list of users that are in the group
		private ArrayList<String> owners; //the owners of the group
		private ArrayList<Key> groupKeys; //the list of group AES keys
		
		public Group()
		{
			users = new ArrayList<String>();
			owners = new ArrayList<String>();
			groupKeys = new ArrayList<Key>();
		}
		
		public ArrayList<String> getUsers()
		{
			return users;
		}
		
		public ArrayList<String> getOwners()
		{
			return owners;
		}
		
		public void addUser(String user)
		{
			users.add(user);
		}
		
		public void removeUser(String user)
		{
			if(!users.isEmpty())
			{
				if(users.contains(user))
				{
					users.remove(users.indexOf(user));
				}
			}
		}
		
		public void addOwner(String owner)
		{
			owners.add(owner);
		}
		
		public void removeOwner(String owner)
		{
			if(!owners.isEmpty())
			{
				if(owners.contains(owner))
				{
					owners.remove(owners.indexOf(owner));
				}
			}
		}
		
		
		//CRYPTO METHODS
		//MJM282
		
		//getters for AES keys:
		//no arg = most recent key
		//int arg = past key
		public Key getKey()
		{
			if(groupKeys.size() == 0) updateKey();
			return groupKeys.get(groupKeys.size() -1);
		}
		
		public Key getKey(int keyNum)
		{
			return groupKeys.get(keyNum);
		}
		
		//gets the key number
		//no arg = most recent key
		public int getNum()
		{
			if(groupKeys.size() == 0) updateKey();
			return groupKeys.size() -1;
		}
		
		//generates a new key and adds it to the end of list
		public void updateKey()
		{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			try
			{
				KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
				generator.init(128);
				Key latestKey = generator.generateKey();
				
				groupKeys.add(latestKey);
			}
			catch(NoSuchAlgorithmException e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				System.exit(-1);
			}
			catch(NoSuchProviderException e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				System.exit(-1);
			}
		}
	}
}