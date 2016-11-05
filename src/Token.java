import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Token implements UserToken
{
	private String sName; //the name of the Server
	private String uName; //the name of the User
	private String timeStamp;
	private List<String> uGroups; //a list of the User's groups
	
	//basic constructor for Token, sets the server name, username, and a list of the user's groups
	public Token(String s, String u, List<String> g)
	{
		setServer(s);
		setUser(u);
		setGroups(g);
		setTimestamp();
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
	
	private void setTimestamp()
	{
		DateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
		String time = dateFormat.format(new Date());
		timeStamp = time;
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
	
	public String getTimestamp()
	{
		return timeStamp;
	}
}