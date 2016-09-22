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
		setUGroups(g);
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
	
	private void setUGroups(List<String> names)
	{
		uGroups = names;
	}
	
	//probably going to need to be an AddGroup in here to add groups to a token
	//need to read the client/server code again to see if it's going to be needed
	
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