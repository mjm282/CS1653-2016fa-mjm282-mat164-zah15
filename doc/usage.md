# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java -cp  ".;bcprov-jdk15on-155" RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

To shut down the server simply press `ctrl-C`.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java -cp  ".;bcprov-jdk15on-155" RunFileServer [port number]`

Note that the port number argument to `RunFileServer` is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

To shut down the server simply press `ctrl-C`.

## Resetting the Group or File Server

Delete the file `UserList.bin` to reset the Group Server. 

Delete the `FileList.bin` file and the `shared_files/` directory to reset the Filer Server. 

## Running the Driver

To start the driver:
 - Enter the directory containing `driver.class`
 - Type `java -cp  ".;bcprov-jdk15on-155" driver`

Note that a group server and file server must both be running and using separate ports to properly use the driver program.

The driver will ask for the address and port number of the group server. Once it has connected the driver will ask for the address and port number of the file server. After both servers are connected enter your username. If your username exists in the `UserList.bin` file, you will see a list of groups where you have membership. Typing `help` will display a list of commands recognized by the program.

## Creating a user

 - Log into driver (must be a member of ADMIN)
 - Type `cuser`
 - Enter the username of the user to be created

Note that adding the user does not put them into a group (See: Adding a user to group). Also, a user cannot be created if desired username already exists in the system.

## Deleting a user

 - Log into driver (must be a member of ADMIN)
 - Type `duser`
 - Enter the username of the user to be deleted

Note that `UserList.bin` will not be refreshed until the user reconnects.

## Creating a group

 - Log into driver
 - Type `cgroup`
 - Enter the name of the group you want to create

## Deleting a group

 - Log into driver (must be a member of ADMIN)
 - Type `dgroup`
 - Enter the name of the group you want to deleted

## Listing members of a group

 - Log into driver
 - Type `lmembers`
 - Enter the name of the group you want to see the members of

Note that you must be a member of the specified group (or ADMIN) in order to see who else is a member.

## Adding a user to a group

 - Log into driver (must be a member of ADMIN)
 - Type `ausertogroup`
 - Enter the name of the group you want to add the user to
 - Enter the name of the user you want to add to the group

## Removing a user from a group

 - Log into driver (must be a member of ADMIN)
 - Type `rmuserfromgroup`
 - Enter the name of the group you want to delete the user from
 - Enter the name of the user you want to delete from the group

## Listing Files

 - Log into driver
 - Type `lfiles`

## Uploading Files

 - Log into driver
 - Type `uploadf`
 - Enter the name of the file to be uploaded, use full file path eg /Users/csstudent/Documents/file.pdf
 - Enter the new name of the file once it is uploaded

Note that the upload destination defaults to the `shared_files` directory. Otherwise a full path must be specified. 

## Downloading Files

 - Log into driver
 - Type `downloadf`
 - Enter the name of the file to be downloaded
 - Enter the new name of the file once it is downloaded

Note that the download destination defaults to the current directory of `FileClient.class` but you can also use a full file path eg /Users/csstudent/Downloads/file.pdf

## Deleting Files

 - Log into driver
 - Type `deletef`
 - Enter the name of the file to be deleted

## Disconnecting

 - Log into driver
 - Type `disconnect`
