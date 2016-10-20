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
- The user authentication with the server will go as follows:
  - Client -> Group Server: Username in plain text
  - Group Server -> Client: {C}k<sub>c</sub> where C is a randomly generated challenge only used once and k<sub>c</sub> is the user's public key
  - Client -> Group Server: C 
  - Group Server -> Client: {k<sub>cs</sub>}k<sub>c</sub>, {{Token}k<sub>s<sup>-1</sup></sub>}k<sub>cs</sub>
- In this situation, we are using a single challenge to authenticate the user to prevent an attacker from claiming to be a user. The server sends a securely generated (using SecureRandom) 256-bit BigInteger encrypted with the user's public key. The user will then decrypt it with their private key and send back the decrypted challenge. The group server, now having verified the user, will send back a 256-bit AES key encrypted with the user's public key in addition to their token which is signed with the server's private key then encrypted with the AES key.

To prevent modified token
- Add field for time-stamp to token to ensure we can make it expire
- Convert token to a byte array and take the SHA 256-bit hash of it
- Sign the hash of the token with the Servers private key
- Send the token and the signed hash back using the procedure outlined above

To verify file server
- The user will initial a connection by sending it the user name and RSA public key
- The server will send back user name in plain text, the RSA public key and time stamp encrypted with the users public key, and the time stamp the user sent +1 encrypted signed with the server private key (to further prove the servers ID)
- The user will generate a fingerprint by generating a SHA-256 hash of the servers 2048bit RSA key, and confirm it against a hash sent to them over another form of communication (USPS, email, SMS, BBM, etc). The client will decrypt the challenge with the provided public key, and vefiry that it is the time stamp it last sent +1.
- If the user confirms the fingerprint it will send back it user name in plain text and a AES key and time stamp encrypted with the servers public key
- The server will confirm it got the key by sending back the user name in plain text and the user's challenge time-stamp + 1 encrypted with the AES key
- If the time stamp is decrypted/valid and send back using the AES key the user will send the user name in plaintext and the token, token signature, and time stamp encrypted using the AES key
- In this case the user is always sending the current time stamp, and the server sends back the time stamp+1 to verify that the server is decrypting everything properly and not just sending time stamps encrypted wiht the user's public key (since we DO NOT trust the server)

Prevent information leakage
- In addition to all the initial set up all information will be headed with the user name in plain text, and the file/command and a time stamp encrypted using 256bit AES generate for the file server or group server
- The client and servers will store the most recent time stamp seen and sent not accept anything older than it when receiving. Some of the confirmations will be sending the time stamp +1 and this will be compared against the time stamp that was sent.

##Assumptions
- Client and Server(s) have in sync clocks, using something like NTP on the same time server (ex pool.ntp.org)
