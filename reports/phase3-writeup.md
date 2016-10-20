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
To establish connection / obtain token
- Upon user creation, an 2048 bit public and private RSA keypair is created and given to the user in a .bin file. Assume the admin creating the account is trusted and puts the keypair on some form of secure media given to the user. The server will store a list of public keys and their correspondence to usernames.
  - Reasons for keysize of 2048: 
    - Uses less CPU
    - Supported on most hardware
    - Key lifespan offered by 2048 bits is sufficient for the systems intents and purposed
- The user authentication with the server will go as follows:
  - Client -> Group Server: Username in plain text
  - Group Server -> Client: {C}k<sub>c</sub> where C is a randomly generated challenge only used once and k<sub>c</sub> is the user's public key
  - Client -> Group Server: C 
  - Group Server -> Client: {k<sub>cg</sub>}k<sub>c</sub>, {{Token}k<sub>g<sup>-1</sup></sub>}k<sub>cg</sub>
- In this situation, we are using a single challenge to authenticate the user to prevent an attacker from claiming to be a user. The server sends a securely generated (using SecureRandom) 256-bit BigInteger encrypted with the user's public key. The user will then decrypt it with their private key and send back the decrypted challenge. The group server, now having verified the user, will send back a 256-bit AES key encrypted with the user's public key in addition to their token which is signed with the server's private key then encrypted with the AES key.
  - Reasons for keysize of 256: 
    - [256 is Government standard for Top Secret information] (http://csrc.nist.gov/groups/STM/cmvp/documents/CNSS15FS.pdf)
    - It would take at least 1 billion computers 2^34 years to look at less than .01% of all key possibilities

To prevent modified token
- To allow keys to expire and prevent modification, timestamps are attached to tokens by groupserver
- Concatenate the information in the Token into one string using string builder
- Hash the concatenated string using SHA-256 and sign it using the Group servers private 2048bit RSA key
- Add the signature to the token
- The user will be able to concatenate the fields and verify it against the signed string


To verify file server
- Verification of the file server will go as follows:
  - The client opens a socket connection with the file server
  - File Server -> Client: k<sub>f</sub>
    - The client computes the hash of the server's public key and verifies it against a known hash securely given to the user by the file server's administrator
    - The client will save the public key hash and alerts the user if the server's key being sent changes
  - Client -> File Server: {C}k<sub>f</sub>
  - File Server -> Client: C
  - Client -> File Server: {{Token}k<sub>g<sup>-1</sup><sub>}k<sub>cf</sub>, {k<sub>cf</sub>}k<sub>f</sub>
- In this situation, we verify the user simply through having a signed token, but need to verify the file server. When attempting to connect the server will send its public key, which the user will then hash and verify with some form of offline verification (USPS, email, SMS, BBM, etc.) with the file server's admin. The user will then send a Securely generated random 256-bit BigInteger back to the server, encrypted with the now verified public key of the file server. The file server authenticates itself by sending back the decrypted challenge. The client will then generate a 256-bit AES key and send it to the file server encrypted with the server's public key as well as the signed token recieved from the group server encrypted with the AES secret key.

Prevent information leakage
- AES key pairs keeps information encrypted throughout the entire communication session so long as session keys are properly distributed. Session keys are not reused and are genereted on connection time after servers are authenticated. See mechanisms above for authentication procedures. 

##Assumptions
- Client and Server(s) have in sync clocks, using something like NTP on the same time server (ex pool.ntp.org)
