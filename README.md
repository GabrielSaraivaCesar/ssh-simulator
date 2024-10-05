# SSH Simulator

I was rencently studing about the SSH service and I decided to create a simple simulator to understand better how it works.

This simulator is a simple implementation of the SSH service, trying to simulate how SSH handshake works and how it ensures confidentiality and integrity of transmitted data.

Run the script with the following command:
```shell
$ python3 ssh_simulator.py
```

Output Example:
```
-----------------

[SSH Handshake]
Server: Challenge is '2341'
Client: Signature is [17091634, 13940868, 13875618, 22784527]
Server: Signature is valid. Client authenticated successfully!

-----------------

[SSH Session Start]

[Diffie-Hellman Key Exchange]
Server: Generated DH public value 13 and signed it.
Client: Generated DH public value 18

Exchange public DH values between client and server...

Client: Verifying server's DH public value signature...
Client: Signature of DH value is valid.

Server: Computed shared secret (session key): 13
Client: Computed shared secret (session key): 13

Shared secret successfully established!

-----------------

Client: Sending command 'ls' encrypted with session key...
Client: Encrypted command is 'y' with HMAC ccf1ba381a8297d83987e1d1839cd6c575c6b1bd0ee425eedfe463ffe856d9d0

-----------------

Server: Decrypting the command and verifying HMAC...
Server: Received command is 'ls' and HMAC is valid.
Server: Encrypted response is '----svyr>;----svyr?;----qvrp|><' with HMAC 8998419f425eff8dcaa7b7b07bcf2530745bd5151a4ee820778f7a003a635543

-----------------

Client: Decrypting the response and verifying HMAC...
Client: HMAC is valid. Decrypted response is:

    file1.txt
    file2.txt
    directory1/
```