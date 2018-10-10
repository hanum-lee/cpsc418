List of the files submitted
  - secureFile.java
  - decryptFile.java
  - readme.txt
Description of each file:
  - secureFile.java
  It encrypts the file inputed with a AES using key that is derived from the seed that user has inputted. The type of PRNG I used is SecureRandom class that is included in the java security packet. The source of the randomness is the seed that user inputed as ASCII string. To put digest into the message being encrypted, I compute the hash value of the original message and append that at the end of the original message.

  - decryptFile.java
 This file decrypts the input file into readable file after checking if the file was altered or not.
 Since we know that the SHA1 hash value will be always of length 20, and I am appending the hash value of the message at the end, we can safely assume that last byte array of length 20 will be the hash value. The method of authenticating that I am using is checking the digest that is appended at the message decrypt, which is a SHA1 hash of the original message, with the hash value of the decrypted message without the digest to see if they match. If they match, that means that the message was not altered during the transition.

How to compile and use the file:
javac secureFile.java
java secureFile [plaintext-filename] [ciphertext-output-filename] [seed]

javac decryptFile.java
java decryptFile [ciphertext-filename] [plaintext-output-filename] [seed]   

The environment that the programs are developed is MacOS 10.12.6 and also tested in MS160 Linux computer.

The programs do:
  - encrypting txt, jpg, zip file
  - checks if it has been altered
  - decrypts the encrypted file if nothing is altered

Bugs:
  - If the seed provided at decryption does not match with seed that is used in encryption, it throws exception. 