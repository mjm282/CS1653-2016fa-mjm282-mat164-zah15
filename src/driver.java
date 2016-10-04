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
				Thread.sleep(5000);
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
				Thread.sleep(5000);
			}
			catch(Exception e){
				System.out.println("Connection Interrupted: " + e);
			}	
		}while (!fClient.isConnected());
		
		
		String groupCommand;
		ArrayList<String> gcArr = new ArrayList<String>();
		
		String username;
		String groupName = "test"; // Fake groupName so that it compiles
		UserToken yourToken;

		System.out.println("Please enter your username");
		username = scan.next();
		yourToken = gClient.getToken(username);
		System.out.println("Your Groups: " + yourToken.getGroups());
		
		while(gClient.isConnected())
		{
			System.out.println("Main Menu");
			System.out.println("Create User: cuser");
			System.out.println("Delete User: duser");
			System.out.println("Create Group: cgroup");
			System.out.println("Delete Group: dgroup");
			System.out.println("List Group Members: lmembers");
			System.out.println("Add User to Group: ausertogroup");
			System.out.println("Remove User from Group: rmuserfromgroup");
			System.out.println("Disconnect: disconnect");
			
			groupCommand = scan.next();
			
			if(groupCommand.equals("cuser"))
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
				List<String> listMembers = gClient.listMembers(groupName, yourToken);
				
				if (listMembers == null)
				{
					System.out.println("Permission Denied");
				}
				else
				{
					System.out.println(listMembers.toString());
				}
			}
			else if(groupCommand.equals("ausertogroup"))
			{
				System.out.println("Please enter a group to add a user");
				groupName = scan.next();
				System.out.println("Please enter the user to add to group" + groupName);
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