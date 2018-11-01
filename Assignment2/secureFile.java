import java.io.*;
import javax.crypto.spec.*;

/**
 * This program performs the following cryptographic operations on the input file:
 *   - computes a random 128-bit key (1st 16 bits of SHA-1 hash of a user-supplied seed)
 *   - computes a HMAC-SHA1 hash of the file's contents
 *   - encrypts the file+hash using AES-128-CBC
 *   - outputs the encrypted data
 *
 * Compilation:    javac secureFile.java
 * Execution: java secureFile [plaintext-filename] [ciphertext-filename] [seed]
 *
 * @author Mike Jacobson
 * @version 1.0, September 25, 2013
 */
public class secureFile{

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

	    // append HMAC-SHA-1 message digest
	    byte[] hashed_msg = CryptoUtilities.append_hash(msg,key);

	    // do AES encryption
	    byte[] aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);

	    // output the ciphertext
	    out_file.write(aes_ciphertext);
	    out_file.close();
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