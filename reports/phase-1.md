## Group Members
Matthew Turley (mat164@pitt.edu)
Zachary Hankinson (zah15@pitt.edu)
Matthew Melchert (mjm282@pitt.edu)

## Section 1: Security Properties
1. Only a trusted user may create or delete users. 
  * This is to ensure that that only authorized users may access the system, assuming that it is a private system.
2. Any user *u* may create a group, however only users with certain priveleges may delete them.
  * This is to ensure that nobody can delete anybody else's group, but anyone in the system may make a group to share files. This makes no assumption of the threat model. 
3. Only certain user may add/remove any other user *u* to/from group *g*, however all users may remove themselves from groups. 
4. A user must be a member of group *g* to upload any file *f* to be shared with that group.
5. If a file *f* is shared with a group *g*, a user must be a member of group *g* to view/edit/download *f*.
6. User must be authenticated to access the system.
  * This is to ensure a user is who they say they are. 
7. All groups must include at least one user who can delete files.
  * This ensures files are alway able to be deleted. 
8. User must verify their identity to his or her activate account.
   * This is to ensure credentials are only possessed by valid users.
9. Anyone can create a user or delete his or her own account but only certain users may delete other users.
  * This is assuming a public file system, so that self-service account creation can be facilitated while maintain malicious users from modifying other accounts.
10. File creators may specify file permissions on files that they own.
  * This is to facilitate file sharing.
11. File ownership is transferable by the current owner to another user
  * This is to ensure that files can be transferred, but only with the consent of the current owner.4
12. Only certain file types and sizes may be allowed. 
  * This safeguards against potentially malicious file types entering the system. 
13. User sessions may expire afer a set period of inactivity. 
  * The keeps an unauthorized user from accessing an authorized account
14. Data must transmittd in a way that does not allow it be accessed if intercepted. 
  * Without this policy anyone could listen and seize confidential data. 
15. A user may only access file-sharing service from a set amount of devices at once. 
  * This keeps users from being impersonated while actively using the system. 

## Section 2: Threat Models
1. Public file sharing system:
  * Users may access the system to perform all authorized activities from any internet connected client device. Users must verify them identify via email to create an account, or may be added directly to the system by a system administrator. Users must authenticate upon login in order to gain access to their account.
  * It is assumed that anyone can listen in on the communications though the internet between the client and file sharing service.
2. Semi-Private System: Campus-wide sharing
  * Users may use the system to upload, download, and edit shared files between other members on a campus network. Users must be connected to the campus network in order to access the system. Users must be added by an administrator to access the system and must verify their identity upon access to the system. If a user wants to connect to the system remotely, they must connect to the campus' network via a VPN. 
  * It can be assumed that anybody on the campus' network may be listening in on the communications through the network. Servers on the network may be able to connect to the broad internet. 


## Section 3: References
