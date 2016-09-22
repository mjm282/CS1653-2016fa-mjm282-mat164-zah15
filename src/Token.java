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
	
	public String getIssuer()
	{
		return sName;
	}
	
	public String getSubject()
	{
		return uName;
	}
	
	public List<String> getGroups()
	{
		return uGroups;
	}
}