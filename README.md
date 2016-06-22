# AnONIONmail - anonymous email system

## Abstract
The basic idea is an anonymous email system. Users can request accounts from the server. 
The user suggests a pseudonym and has to send his public key and a hashed password. 
If the pseudonym is available, the user's data is added to a list on the server. The pseudonym 
is used to identify the user. A registered user can then send an email by requesting the other 
one's public key from the server and encrypt a symmetric key. This symmetric key is also 
used for encrypting the message. Then, the encrypted message (with symmetric key) and 
the encrypted symmetric key (with other's public key) are stored on the server. After 
authenticating, the receipient can then poll for new messages on the server. The server is 
running on Google App Engine. As an additional step, the server on App Engine can be 
accessed via a Tor Hidden Service proxy to guarantee a higher level of anonymity. 

## Subdirectories

`appengine`: Python App for Google App Engine

`client`: Java client

`vm`: configuration commands for the machine running the hidden service


## Server Communication
The JSON protocol is used to transmit data between the client and the server.
Currently HTTP POST request are used to talk to the server. This might change later
with TOR. All data is at least encrypted with the public key of the server, so even
if we used HTTP in the final version, no one can read your data.

## Design Decisions

### Base64
The alorithms to Hash, AES-encrypt/decrypt or RSA-encrypt/decrypt data are using
byte arrays as input and output. So all encrypted and hashed data is stored as byte 
array, but sending byte arrays via JSON to the server is not practical. So all byte arrays
are converted to base64 strings. These strings are then sent to the server via
JSON and the server responds also with base64 strings.

### Modulus
In some cases the client wants to send his RSA public key to the server or he wants 
to receive some other users public key from the server. In this cases the RSA key needs
to be encrypted with the public key of the server of the users public key. A RSA public
key consists of a large modulus and an public exponent. The data which should be encrypted
has not to be larger or equal the modulus. Here is the dilemma, because we want to actually
encrypt such a modulus. To do this, we have to split the modulus into two pieces and 
encrypt them seperately. We choosed to split the modulus (257 bit) into one 200 bit 
piece and one 57 bit piece. The output of the RSA encryption is always 256 bit, regardless
of the size of the input, so an encrypted public key modulus consists of 512 bit. When
decrypting this modulus, we again have to split it into two smaller pieces. This time 
we need two 256 bit moduli, so we split the big modulus in the middle and decrypt
the smaller pieces seperately. After decrypting, we get one 200 bit modulus and one
57 bit modulus, so we have to merge both to the final 257 bit modulus and so we got
the original modulus again. Together with the public exponent we have a correct 
public key.
