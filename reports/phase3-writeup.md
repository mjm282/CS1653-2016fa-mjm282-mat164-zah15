#Mechanism Description
##Description of Threats:
T1 - Unauthorized Token Issuance
- The state that our current file-sharing system is in allows for illegitimate clients to request tokens from the group server. As a result, anyone can impersonate anyone else with only a username. Without proper token issuance, an imposter could take over an administrative account and seize control of all files on any server. Additionally, the attacker could modify the existence or privileges of any group/user that has access to the system. 
- In the event that our system is used for campus/company file sharing, any unauthenticated token that passes through the system could result in loss of integrity, availability, and confidentiality for both individual users and multi-user groups. 

T2 - Token Modification/Forgery
- In the current, insecure, file-sharing system a user’s token isn’t explicitly presented to them other than a list of groups the user is in upon signing in with their username. When any request to the group or file server is made, the user’s token is sent along with it and those functions checks the token to to see if the token exists in the userlist, then the list of groups they belong to, etc. However, an attacker may easily, if they have access to network traffic and know the message structure, send a token with anybody’s name, even an administrator to carry out tasks. Furthermore they could edit the token in/before transit to add in a group tag that they are not meant to be in.
- If a malicious user decided to abuse the system they could do things including, but not limited to: posing as a member of the ADMIN group and deleting every user, group, and file on the system.

T3 - Unauthorized File Servers
- As it stands now, users have no assurance that the file server they connect to is the one they actually require access from. There is a possibility that the servers themselves may be impersonated or even compromised. If such an event were to occur, the imposter server could retrieve/view incoming tokens and then replicate them in a way that would allow them to impersonate that same user on the system. As a result, the same potential outcomes from threat T1 could arise. 
- An imposter server viewing incoming tokens and/or uploaded files violates confidentiality. Additionally, the confusion that could ensue would potentially violate both integrity and availability. 

T4 - Information Leakage via Passive Monitoring
- All data is currently sent to the server/client in plain text. Anyone who has access to the network can run a wireshark type attack and see what is being transferred, making it possible to steal another user’s token or file download/upload. This makes the above attacks, such as token forgery/manipulation, possible.

##Description of Mechanisms
-  User will use a password to ID themselves, the hash of the password will be generated client side and encrypted before being sent and salted by the server for verification and storage. Sending the password will be encrypted using the server's public key, and also include a challenge to include replay attacks. If the server accepts the password it will use the client's public key to sent back the challenge, token, and an AES key for further communication with the group server.
- For initial communication with the file server the token and a challenge will be sent encrypted with the file server's public key. If the file server accepts the token it will send back the challenge and an AES key encrypted with the client's public key. The AES key will be used for all further communication, and expire upon the token's expiration.
- In order to combat the threat of token forgery/modification, we decided to have the group server attach a timestamp to each token and sign the entire token with the server’s private key. The token is then IMMEDIATELY sent from the user to the file server the user wishes to connect to and used for the rest of the session.  The timestamp attached to the token will expire after a set period of time and the group server will generate a new token with a current timestamp to be sent to the user / file server. 
  - The signed token will prevent any token modification, as the token will have to be sent with the signature to the file server.
  - Immediately sending the token to the file server along with a timestamp assures that tokens being sent can not be replayed
  - Tokens will expire when the session ends or after a set period of time to assure that the token is fresh
  - Authenticated file server will only accept a token that was timestamped by the server within five minutes of the attempted connection and store the most recent token. If a token older than the most recent is sent, it will not be accepted.
- Have a fileserver give a SHA256 hash of its public key to identify itself to be verified offline similar to SSH
  - Fulfills protection against threat T3
