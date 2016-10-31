// Main Driver

import java.io.*;
import java.util.*;

public class driver
{
	public static void main(String [] args)
	{
		GroupClient gClient = new GroupClient();
		Scanner scan = new Scanner(System.in);
		
		System.out.println("Please enter the address of your Group Server");
		String groupAddress = scan.next();
		System.out.println("Please enter the port of your Group Server (default 8765)");
		int groupPort = scan.nextInt();
		do
		{
			
			try
			{
				gClient.connect(groupAddress, groupPort);
				//Thread.sleep(5000);
			}
			catch(Exception e){
				System.out.println("Connection Interrupted: " + e);
			}	
		}while (!gClient.isConnected());
		
		FileClient fClient = new FileClient();
		System.out.println("Please enter the address of your File Server");
		String fileAddress = scan.next();
		System.out.println("Please enter the port of your File Server (default 4321)");
		int filePort = scan.nextInt();
		do
		{
			
			try
			{
				fClient.connect(fileAddress, filePort);
				//Thread.sleep(5000);
			}
			catch(Exception e){
				System.out.println("Connection Interrupted: " + e);
			}	
		}while (!fClient.isConnected());
		
		
		String groupCommand;
		ArrayList<String> gcArr = new ArrayList<String>();
		
		String username;
		String groupName = "test"; // Fake groupName so that it compiles
		String sFile = "test";
		String dFile = "test";
		UserToken yourToken;

		System.out.println("Please enter your username");
		username = scan.next();
		yourToken = gClient.getToken(username);
		if(yourToken == null)
		{
			System.out.println("ERROR: Unable to retrieve token, make sure your username is correct!");
			gClient.disconnect();
			fClient.disconnect();
			System.exit(0);
		}
		System.out.println("Your Groups: " + yourToken.getGroups());
		System.out.println("Type 'help' for a list of commands");
		while(gClient.isConnected())
		{
			
			groupCommand = scan.next();
			if(groupCommand.equals("help"))
			{
				System.out.println("Create User: cuser"); // Done
				System.out.println("Delete User: duser"); // Done
				System.out.println("Create Group: cgroup"); // Done
				System.out.println("Delete Group: dgroup"); // Done
				System.out.println("List Group Members: lmembers"); // Done
				System.out.println("Add User to Group: ausertogroup"); // Done
				System.out.println("Remove User from Group: rmuserfromgroup"); // Done
				System.out.println("List Files: lfiles"); // Done
				System.out.println("Upload File: uploadf"); // Done
				System.out.println("Download: downloadf "); // Done
				System.out.println("Delete File: deletef");
				System.out.println("Disconnect: disconnect"); // Done				
			}
			else if(groupCommand.equals("cuser"))
			{
				System.out.println("Please enter the new username");
				username = scan.next();
				if (!gClient.createUser(username, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			else if(groupCommand.equals("duser"))
			{
				System.out.println("Please enter the username to be deleted");
				username = scan.next();
				if (!gClient.deleteUser(username, yourToken))
				{
					System.out.println("Permission Denied");
				}
				
			}
			else if(groupCommand.equals("cgroup"))
			{
				System.out.println("Please enter the group name to be created");
				groupName = scan.next();
				if (!gClient.createGroup(groupName, yourToken))
				{
					System.out.println("Permission Denied");
				}
				
			}
			else if(groupCommand.equals("dgroup"))
			{
				System.out.println("Please enter the group name to be deleted");
				groupName = scan.next();
				if (!gClient.deleteGroup(groupName, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			else if(groupCommand.equals("lmembers"))
			{
				System.out.println("Please enter the group name to have members listed");
				groupName = scan.next();
				List<String> lMembers = gClient.listMembers(groupName, yourToken);
				
				if (lMembers == null)
				{
					System.out.println("Permission Denied");
				}
				else
				{
					System.out.println(lMembers.toString());
				}
			}
			else if(groupCommand.equals("ausertogroup"))
			{
				System.out.println("Please enter a group to add a user");
				groupName = scan.next();
				System.out.println("Please enter the user to add to group " + groupName);
				username = scan.next();
				
				if (!gClient.addUserToGroup(username, groupName, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			else if(groupCommand.equals("rmuserfromgroup"))
			{
				System.out.println("Please enter a group to remove a user");
				groupName = scan.next();
				System.out.println("Please enter the user to remove from group" + groupName);
				username = scan.next();
				
				if (!gClient.deleteUserFromGroup(username, groupName, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			
			else if (groupCommand.equals("lfiles"))
			{
				System.out.println(fClient.listFiles(yourToken));
			}
			
			else if (groupCommand.equals("uploadf"))
			{
				System.out.println("Please Choose a Source File");
				sFile = scan.next();
				System.out.println("Please Select a Destination File Name");
				dFile = scan.next();
				System.out.println("Please Choose a Group to Share With");
				groupName = scan.next();
				if (!fClient.upload(sFile, dFile, groupName, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			
			else if (groupCommand.equals("downloadf"))
			{
				System.out.println("Please Choose a Source File");
				sFile = scan.next();
				System.out.println("Please Select a Destination File Name");
				dFile = scan.next();
				if (!fClient.download(sFile, dFile, yourToken))
				{
					System.out.println("Permission Denied");
				}
			}
			
			else if (groupCommand.equals("deletef"))
			{
				System.out.println("Please Choose a File to Delete");
				sFile = scan.next();
				if (!fClient.delete(sFile, yourToken))
				{
					System.out.println("File does not Exist");
				}
			}
			
			else if(groupCommand.equals("disconnect"))
			{
				// Close Connections
				gClient.disconnect();
				fClient.disconnect();
				// Quit the Application
				System.exit(0);
			}
		}
	}
}