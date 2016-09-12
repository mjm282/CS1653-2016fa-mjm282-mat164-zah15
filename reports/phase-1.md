## Group Members
Matthew Turley (mat164@pitt.edu)
Zachary Hankinson (zah15@pitt.edu)
Matthew Melchert (mjm282@pitt.edu)

## Section 1: Security Properties
1. Only a trusted user may create or delete users
  * This is to ensure that that only authorized users may access the system, assuming that it is a private system.
2. Any user *u* may create a group, however only users with certain priveleges may delete them.
  * This is to ensure that nobody can delete anybody else's group, but anyone in the system may make a group to share files. This makes no assumption of the threat model
3. Only certain user may add/remove any other user *u* to/from group *g*, however all users may remove themselves from groups
4. A user must be a member of group *g* to upload any file *f* to be shared with that group
5. If a file *f* is shared with a group *g*, a user must be a member of group *g* to view/edit/download *f*
6. User must be authenticated to access the system.
  * This is to ensure a user is who they say they are
7. All groups must include at least one user who can delete files.
  * This ensures files are alway able to be deleted. 
8. User must verify their identity to his or her activate account.
   * This is to ensure credentials are only possessed by valid users.
9. Anyone can create a user or delete his or her own account but only certain users may delete other users.
  * This is assuming a public file system, so that self-service account creation can be facilitated while maintain malicious users from modifying other accounts.
10. File creators may specify file permissions on files that they own.
  * This is to facilitate file sharing.
11. File ownership is transferable by the current owner to another user
  * This is to ensure that files can be transferred, but only with the consent of the current owner.

## Section 2: Threat Models
1. Public file sharing system:
  * 
2. Private, invitation based system: 


## Section 3: References
