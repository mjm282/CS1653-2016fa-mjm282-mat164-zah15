import java.util.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.lang.StringBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import javax.crypto.*;

public class Token implements UserToken
{
	private String gServer; // The issuing Group Server
	private String fServer; // The valid for File Se
	private String userName; //the name of the User
	private List<String> uGroups; //a list of the User's groups
	private long timeStamp; // The time the token was issued
	private byte[] sig;  // The digital signature of the token, to prevent modification

	//basic constructor for Token, sets the server name, username, and a list of the user's groups
	public Token(String gServ, String uName, List<String> groups, PrivateKey prK, String fServ)
	{
		setGServer(gServ);
		setFServer(fServ);
		setUser(uName);
		setGroups(groups);
		setTimestamp();
		setSign(prK);
	}

	private void setSign(PrivateKey sPrivKey)
	{
		StringBuilder mySign = new StringBuilder();
		mySign.append(gServer);
		mySign.append(fServer);
		mySign.append(userName);
		Collections.sort(uGroups); // Sort uGroups
		mySign.append(uGroups);
		mySign.append(timeStamp);
		String myString = mySign.toString(); // Our Comparison Point
		try
		{
			Signature signature = Signature.getInstance("SHA256withRSA", "BC");
			signature.initSign(sPrivKey, new SecureRandom());
	    	signature.update(myString.toString().getBytes());
			sig = signature.sign();
		}
		catch (Exception e)
		{
			System.out.println("An Error Had Occured");
		}
	}

	public boolean verifySignature(PublicKey sPubKey)
	{
		Security.addProvider(new BouncyCastleProvider());
		// Build the StringBuilder
		StringBuilder mySign = new StringBuilder();
		mySign.append(gServer);
		mySign.append(fServer);
		mySign.append(userName);
		Collections.sort(uGroups); // Sort uGroups
		mySign.append(uGroups);
		mySign.append(timeStamp);
		String myString = mySign.toString(); // Our Comparison Point
		try
		{
			// And that stuff for the signiture
			Signature signature = Signature.getInstance("SHA256withRSA", "BC");
			signature.initVerify(sPubKey);
	    	signature.update(myString.getBytes());
			 if(signature.verify(sig))
			 {
				 return true;
			 }
			 else
			 {
				 return false;
			 }
		}
		catch (Exception e)
		{
			System.out.println("An Error Had Occured");
			return false;
		}
	}



	//setters and getters for the class
	private void setGServer(String name)
	{
		gServer = name;
	}
	
	private void setFServer(String name)
	{
		fServer = name;
	}

	private void setUser(String name)
	{
		userName = name;
	}

	private void setGroups(List<String> names)
	{
		uGroups = names;
	}

	private void setTimestamp()
	{
		long unixTime = System.currentTimeMillis() / 1000L;
		timeStamp = unixTime;
	}

	//adds a group to the list of groups
	//if the group already exists, returns false
	public boolean addGroup(String g, PrivateKey sPrivKey)
	{
		if (uGroups.indexOf(g) == -1)
		{
			uGroups.add(g);
			setSign(sPrivKey);
			return true;
		}
		else return false;
	}

	//deletes a group from a user's group list
	//if the group doesn't exist return false
	public boolean removeGroup(String g, PrivateKey sPrivKey)
	{
		if(uGroups.indexOf(g) != -1)
		{
			uGroups.remove(g);
			setSign(sPrivKey); // Update signature 
			return true;
		}
		else return false;
	}

	//used the UserToken interface's methods as the class' getters
	//returns the server name
	public String getIssuer()
	{
		return gServer;
	}
	
	// Need to get the valid File Server
	public String getIssuee()
	{
		return fServer;
	}

	//returns the user's username
	public String getSubject()
	{
		return userName;
	}

	//returns all of the groups that the user is in
	public List<String> getGroups()
	{
		return uGroups;
	}

	public long getTimestamp()
	{
		return timeStamp;
	}
}
