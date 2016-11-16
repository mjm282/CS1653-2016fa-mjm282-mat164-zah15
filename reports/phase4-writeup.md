#Mechanism Description
##Description of Threats:
T5 - Message Reorder, Replay, or Modification:
- Messages sent through our file-sharing system are encrpyted but have no means of detecting any modifications upon delivery.
Additionally, there is potential for an active attacker to save or reorder messages they intercept. Ignoring these scenarioes could
lead to harmful/unintended changes to be made to users, groups, and files as well as the permissions associated with each. 

T6 - File Leakage:
- Our current file-sharing system assumes that file servers can be trusted so long as they are properly authenticated. However, if they
are completely untrusted, there is no protection against a malicious file server leaking files stored in plain text. 

T7 - Token Theft:
- In addition to leaking files, a malicious file server could also impersonate an active user by taking their token. 
