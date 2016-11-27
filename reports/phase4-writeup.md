#Mechanism Description

##Description of Threats:

T5 - Message Reorder, Replay, or Modification:

- Messages sent through our file-sharing system are encrypted but have no means of detecting any modifications upon delivery. Additionally, there is potential for an active attacker to save or reorder messages they intercept. Ignoring these scenarios could
lead to harmful/unintended changes to be made to users, groups, and files as well as the permissions associated with each.

T6 - File Leakage:

- Our current file-sharing system assumes that file servers can be trusted so long as they are properly authenticated. However, if they are completely untrusted, there is no protection against a malicious file server leaking files stored in plain text.
- We are assuming a user who has been removed from a group already has all the old files, but we do not want them to be able to access any new files that have been shared to the group. So everytime a user is removed from the group we need to update the group key.

T7 - Token Theft:

- In addition to leaking files, a malicious file server could also impersonate an active user by taking their token.

##Solution:

T5: Message Reorder, Replay, or Modification

- As we did our initial authentication using Public Key crypto for authentication very few changes will need to be made to our handshake protocol.

- A counter value, starting with zero, will be started at the start of the session, to maintain order. The message recipient will check the counter value against a cached value of the previous message&#39;s counter value to ensure messages were received in order (make sure that the number is greater than the previous), maybe send back some warning if it appears a message has been dropped but that&#39;s secondary.  To prevent message modification a HMAC will be used. There will be four counters, one for the file server sending, one for the group server sending, one for the client to talk to the group server, and one for the client to talk to the file server. The separate counters are to insure that packets lost in transit do not throw off the counter.
- The user authentication with the server will go as follows:
  - Client -&gt; Group Server: Username in plaintext, {Counter1}ks
  - Group Server -&gt; Client: {C1}kc, Counter2 where C is a randomly generated challenge only used once and kc is the user&#39;s public key
  - Client -&gt; Group Server: C1, {C2, Counter1}ks
  - Group Server -&gt; Client: C2, {kcg}kc, {{Token}kg-1, counter
# 2
}kcg
- Verification of the file server will go as follows:
  - The client opens a socket connection with the file server
  - File Server -&gt; Client: kf
    - The client computes the hash of the server&#39;s public key and verifies it against a known hash securely given to the user by the file server&#39;s administrator
    - The client will save the public key hash and alerts the user if the server&#39;s key being sent changes
  - Client -&gt; File Server: {C}kf, {Counter1}ks
  - File Server -&gt; Client: C, {Counte2}kc
  - Client -&gt; File Server: {{Token}kg-1 , Counter
# 1
}kcf, {kcf}kf
- For all other communication
  - Client -&gt; Server: {Command, Arguments, Counter1}SK, IV, HMAC
  - Server -&gt; Client: {Result, Data, Counter2}SK, HMAC

T6: File Leakage

- In order to prevent file leakage, we will have a &quot;group key&quot; assigned to each group that a file is shared for. These group keys will be stored as an ArrayList, each value in the ArrayList will be an AES key. This will allow us to implement backwards secrecy. Whenever a user is removed from a group, that number is incremented and a new AES key is generated and the pair are added to the list. Users who were removed from groups, if they saved their original AES key, can still potentially decrypt files that were added to the server before they were removed, but we&#39;re assuming they would have downloaded them anyways.
- When files are transmitted to the file server to be saved, the file name will be appended with the value  &quot;k\_&quot;, where &quot;k&quot; is the number of the most recent key iteration for that group.
- The IV will also be saved along with the file, as each file needs its own IV to prevent a ECB from being built for each key.
- When a user needs to encrypt a file to be sent to the file server for storage, they send a message to the group server, the server will validate that they are still a member of that particular group, and send back the most recent iteration of their group AES key. The client will then encrypt the file with CBC, append &quot;k\_&quot; and perform the normal upload procedure from Phase 3
- To download and decrypt the file, they will perform the normal download procedure from Phase 3. The client will then strip the &quot;k\_&quot; from the file and send a message to the group server requesting an AES key and IV, including the group the file belongs to, as well as  k in the message. The group server will then validate that the user is still a member of the group that the file belongs to, and if they do they&#39;ll send the proper key and IV to the client for decryption.
- Stored on File Server: Index, IV, {File}GK

T7: Token Theft

- In the token have a field for the file server it is valid for. This is to prevent a malicious file server from attempting to use the token on another file server. While it will not prevent the file server from giving the token to other users on the file server, the file server never knows the key that the files are encrypted with preventing unauthorized users from being able to decrypt any files.
- To ensure that the token does not get modified to allow its use on a new server the token will include a digital signature over its data. The signature will be over: the group server that issued the token, the file server the token is allowed on, the user name, the sorted list of the groups the user is a member of.
- {H(Group Server Address, File Server Address, User Name, Sorted Groups)}kg-1

All protocols from phase 3 are still kept in place to ensure security against unauthorized token issuance, token modification, unauthorized file servers, and information leakage.
