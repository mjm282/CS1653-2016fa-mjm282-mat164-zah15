# Mechanism Description

## Description of Threats:

T8. Key File, GroupList.bin, gets leaked
  - In our implementation, GroupList.bin is a plaintext file that contains a Hashtable of group names mapped to groups. Each group contains three ArrayLists of data: Users, Owners, and GroupKeys. As it stands, all of this is stored entirely in plain text and our group server simply opens the file with a FileInputStream on startup.
  - If GroupList.bin gets leaked all the AES keys for decrypting files are stored in plain text and able to be used to decrypt any leaked files or by a malicious file server to see what is being stored.

T9. Availability Attacks
  - Messages sent in our file sharing system include headers sent in plain-text (i.e., SHAKE, GET, OK, FAIL, DISCONNECT). A passive adversary could potentially see exactly when a handshake takes place as well as any events where requests received result in success or failure.
  - Knowing this information, an attacker could launch an availability attack on the system by removing/modifying the plaintext portions of messages. (Example: Changing GET to DISCONNECT)

## Solutions:

T8. KeyFile gets leaked
  - Have the trusted Admin of the GroupServer have a password that only he knows. This password is used to verify the admin is the one initializing the server, and allows the decryption of the GroupList.bin file.
  - When the server is started for the first time, the trusted Admin will be asked to create a password. A random 256-bit AES key that will be used to encrypt GroupList.bin will be created, encrypted with a 256-bit AES key generated using the Admin’s password. This will then be stored at the beginning of GroupList.bin. That random 256-bit key will then be used on server startup for subsequent startups
  - On any server startup other than the initial startup, the server will prompt the admin to enter his password. The server will then generate a 256-bit AES key using that password, read in the stored and encrypted AES key at the start of GroupList.bin, decrypt that, then use it to decrypt the rest of the file as it reads it in for use.
  - Every five minutes, and on server close,  our group server runs AutoSave method, which will encrypt the contents of the group list with the 256-bit AES key, and write that to GroupList.bin.
  - Because we are encrypting a random key using the password the Admin is able to change his password as needed (e.g. company policy) and only the 256-AES key will need to be re-encrypted.

T9. Availability Attacks
  - Option 1:
      - Instead of using a plain string as the message header on envelope creation, accessing the message in the code with envelope.getMessage(), message headers will be encrypted with the session key and included as the first object in the envelope. On message retrieval, the client/server will get the message header through envelope.getObjContents(0), and decrypt it with the shared 256-bit AES session key created on the start of the session between client and server.
      - The “GET” tags for handshaking and setting up session keys between client and server will have to be sent with the old method, with its header in plaintext. This is unavoidable because the session key to encrypt these messages will not be created until after the handshake. This is OK, however, because the messages sent back and forth when handshaking follow a very set pattern and if one wanted to interrupt messages and interfere with the handshaking as an availability attack, they would do so encrypted headers or not, and avoiding this issue is out of the scope of the project.
  - Option 2:
    - Instead of using ObjectOutputStream/ObjectInputStream to send and receive message envelopes, the entire message envelope will be serialized, encrypted with the session Key, and sent via a CipherOutputStream. The recipient will then need to read in the message through a CipherInputStream, decrypt the entire envelope, deserialize it, and then decrypt each object in the message with the same key.
    - The “GET” tags will be sent in plaintext for the same reasons outlined in Option 1. 
