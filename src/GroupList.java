import java.util.*;

public class GroupList implements java.io.Serializable
{
	
	//this group list is mostly going to be a straight up clone of UserList.java
	
	private Hashtable<String, Group> gList = new Hashtable<String, Group>();
	
	public synchronized void addGroup(String groupName)
	{
		Group newGroup = new Group();
		gList.put(groupname, newGroup);
	}
	
	public synchronized void deleteGroup(String groupName)
	{
		gList.remove(groupName);
	}
	
	public synchronized boolean checkGroup(String groupName)
	{
		if(gList.containsKey(groupName)) 
		{
			return true;
		}
		else 
		{
			return false;
		}
	}
	
	public synchronized ArrayList<String> getGroupMembers(String groupName)
	{
		return gList.get(groupName).getUsers();
	}
	
	public synchronized ArrayList<String> getGroupOwners(String groupName)
	{
		return gList.get(groupName).getOwners();
	}
	
	public synchronized void addGroupUser(String groupName, String username)
	{
		gList.get(groupName).addUser(username);
	}
	
	public synchronized void removeGroupUser(String groupName, String username)
	{
		gList.get(groupName).removeUser(username);
	}
	
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
	
	
	/* group datatype
	 * contains the list of users that are in a specific group
	 * also contains a list of the owners of that group
	 * can add or remove owners and users to/from individual groups
	 */
	class Group implements java.io.Serializable
	{
		private ArrayList<String> users; //the list of users that are in the group
		private ArrayList<String> owners; //the owners of the group
		
		public Group()
		{
			users = new ArrayList<String>();
			owners = new ArrayList<String>();
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
	}
}