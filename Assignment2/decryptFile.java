import java.io.*;
import javax.crypto.spec.*;

/**
 * This program performs the following cryptographic operations on the input file:
 *   - computes a random 128-bit key (1st 16 bits of SHA-1 hash of a user-supplied seed)
 *   - decrypts the file
 *   - extracts a HMAC-SHA1 digest of the original file contents (from the end of the
 *     decrypted data)
 *   - computes the HMAC-SHA1 digest of the decrypted file contents
 *   - outputs the encrypted data if the computed and decrypted digests are equal
 *
 * Compilation:    javac decryptFile.java
 * Execution: java decryptFile [plaintext-filename] [ciphertext-filename] [seed]
 *
 * @author Mike Jacobson
 * @version 1.0, September 25, 2013
 */
public class decryptFile{

    public static void main(String args[]) throws Exception{
	FileInputStream in_file = null;
	FileOutputStream out_file = null;

	try{
	    // open input and output files
	    in_file = new FileInputStream(args[0]);
	    out_file = new FileOutputStream(args[1]);

	    // read input file into a byte array
	    byte[] msg = new byte[in_file.available()];
	    int read_bytes = in_file.read(msg);

	    // compute key:  1st 16 bytes of SHA-1 hash of seed
	    SecretKeySpec key = CryptoUtilities.key_from_seed(args[2].getBytes());

	    // do AES decryption
	    byte[] hashed_plaintext = CryptoUtilities.decrypt(msg,key);

	    // verify HMAC-SHA-1 message digest and output plaintext if valid
	    if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
		System.out.println("Message digest OK");

		// extract plaintext and output to file
		byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);
		out_file.write(plaintext);
	        out_file.close();
	    }
	    else
		System.out.println("ERROR:  invalid message digest!");
	}
	catch(Exception e){
	    System.out.println(e);
	}
	finally{
	    if (in_file != null){
		in_file.close();
	    }
	}
    }

}