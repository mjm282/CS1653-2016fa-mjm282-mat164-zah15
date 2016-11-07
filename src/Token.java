import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.lang.StringBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import javax.crypto.*;

public class Token implements UserToken
{
	private String sName; //the name of the Server
	private String uName; //the name of the User
	private long timeStamp;
	private List<String> uGroups; //a list of the User's groups
	private byte[] sig;
	private PublicKey sPubKey;

	//basic constructor for Token, sets the server name, username, and a list of the user's groups
	public Token(String s, String u, List<String> g, PrivateKey prK, PublicKey puK)
	{
		setServer(s);
		setUser(u);
		setGroups(g);
		setTimestamp();
		setSign(prK);
		setPublicKey(puK);
	}

	// Stuff For Sign
	private void setPublicKey(PublicKey puK)
	{
		sPubKey = puK;
	}

	private void setSign(PrivateKey sPrivKey)
	{
		Security.addProvider(new BouncyCastleProvider());
		StringBuilder mySign = new StringBuilder();
		mySign.append(sName);
		mySign.append(uName);
		mySign.append(timeStamp);
		mySign.append(uGroups);
		try
		{
			String myString = mySign.toString();
			Signature signature = Signature.getInstance("SHA256withRSA", "BC");
			signature.initSign(sPrivKey, new SecureRandom());
	    signature.update(myString.getBytes());
			sig = signature.sign();
		}
		catch (Exception e)
		{
			System.out.println("An Error Had Occured");
		}
	}

	public boolean verifySignature()
	{
		Security.addProvider(new BouncyCastleProvider());
		// Build the StringBuilder
		StringBuilder mySign = new StringBuilder();
		mySign.append(sName);
		mySign.append(uName);
		mySign.append(timeStamp);
		mySign.append(uGroups);
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
			setSign(sPrivKey);
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

	public long getTimestamp()
	{
		return timeStamp;
	}
}
