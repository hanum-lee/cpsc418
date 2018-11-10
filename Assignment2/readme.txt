1. File Submitted:
	Client.java
	CryptoUtilities.java
	Server.java
	ServerThread.java
2. Description:
	To compile:
		Server:
			javac Server.java
			(For non debugging mode)
			java Server [port] [seed]
			(For debugging mode)
			java Server [port]
		Client:
			javac Client.java
			java Client [ip] [port] [sourceFileName] [destinationFileName] [seed]
	The programs were developed and tested in MacOS 10.12.6 environment
3. What is implemented:
	All of the requirements for the problem are implemented:
		Secure transfering file
		Detecting changed in data
		Debugging mode
4. Known bug:
	Since the server does not take any additional command, you have to force close the terminal in order to close the server.(Assuming server has to be always on)
5. Written description:
	Acknowledgements are sent in int value either 0 for there is a error so file transfer could not be completed, or 1 for everything was transmitted without error.
	The program first hashes the intended message with HMAC-SHA-1 with a random key generated with the inputed seed by user. Then it appeneds the hashed value to the message and encrypts it with AES using the same key.
	Since the message sent over by socket is encrypted by AES and has hash value appended at the end of the plain message, the adversary can't obtain the message or alter with it unless they have the key.
	If adversary somehow breaks the encryption without the key altered message, the program can compute the hash value of the plain message and check with the hash value that was sent with the message.