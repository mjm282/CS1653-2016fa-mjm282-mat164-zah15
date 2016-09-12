## Group Members
Matthew Turley (mat164@pitt.edu)
Zachary Hankinson (zah15@pitt.edu)
Matthew Melchert (mjm282@pitt.edu)

## Section 1: Security Properties
1. Only a Sysadmin, or other trusted user, may create or delete users
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


## Section 2: Threat Models
1. Public file sharing system:
  * 
2. Private, invitation based system: 


## Section 3: References
