import java.util.List;

public class Token implements UserToken
{
	private String sName; //the name of the Server
	private String uName; //the name of the User
	private List<String> uGroups; //a list of the User's groups
	
	//basic constructor for Token, sets the server name, username, and a list of the user's groups
	public Token(String s, String u, List<String> g)
	{
		setServer(s);
		setUser(u);
		setGroups(g);
	}
	
	//setters and getters for the class
	private void setServer(String name)
	{
		sName = name;
	}
	
	private void setUser(String name)
	{
		uName = name;
	}
	
	private void setGroups(List<String> names)
	{
		uGroups = names;
	}

	//adds a group to the list of groups
	//if the group already exists, returns false
	public boolean addGroup(String g)
	{
		if (uGroups.indexOf(g) == -1)
		{
			uGroups.add(g);
			return true;
		}
		else return false;
	}
	
	//deletes a group from a user's group list
	//if the group doesn't exist return false
	public boolean removeGroup(String g)
	{
		if(uGroups.indexOf(g) != -1)
		{
			uGroups.remove(g);
			return true;
		}
		else return false;
	}
	
	//used the UserToken interface's methods as the class' getters
	//returns the server name
	public String getIssuer()
	{
		return sName;
	}
	
	//returns the user's username
	public String getSubject()
	{
		return uName;
	}
	
	//returns all of the groups that the user is in
	public List<String> getGroups()
	{
		return uGroups;
	}
}