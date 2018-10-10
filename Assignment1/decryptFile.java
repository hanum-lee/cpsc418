/***********************



***********************/


import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
import java.util.Arrays;



public class decryptFile{
    private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;
	private static SecureRandom seedRan = null;

	//for DSA
	private static KeyPairGenerator keypairgen = null;
	private static KeyPair keypair = null;
	private static DSAPrivateKey private_key = null;
	private static DSAPublicKey public_key = null;
	private static Signature dsa_sig = null;
	private static SecureRandom secRan = null;
    private static BigInteger big_sig = null;
	private static byte[] seedByte = null;
    
    public static void main(String[] args) throws Exception{
        FileInputStream in_file = null;
		FileInputStream in_file2 = null;
		FileOutputStream out_file = null;
		byte[] sha_hash = null;
		byte[] hmac_hash = null;
		byte[] aes_ciphertext = null;
		byte[] sig = null;
		String decrypted_str = new String();
		int read_bytes = 0;
        boolean verify = false;
        
        try{
            in_file = new FileInputStream(args[0]);
            out_file = new FileOutputStream(args[1]);
            seedByte = args[2].getBytes();

			//Generating random number from the seed given by user
            seedRan = SecureRandom.getInstance("SHA1PRNG");
            seedRan.setSeed(seedByte);
            
            byte[] msg = new byte[in_file.available()];
			read_bytes = in_file.read(msg);



            //encrypt file with AES
			//key setup - generate 128 bit key
			key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(128,seedRan);
			sec_key = key_gen.generateKey();

			//get key material in raw form
			raw = sec_key.getEncoded();
			sec_key_spec = new SecretKeySpec(raw, "AES");

			//create the cipher object that uses AES as the algorithm
			sec_cipher = Cipher.getInstance("AES");	
            
			//parse the hash value and message
			decrypted_str = aes_decrypt(msg);
			byte[] decrptbyte = aes_decrypt_byte(msg);
			byte[] decryp = decrypted_str.getBytes();
			byte[] hashvalue = Arrays.copyOfRange(decrptbyte, decrptbyte.length-20, decrptbyte.length);
			byte[] msgvalue = Arrays.copyOfRange(decrptbyte, 0, decrptbyte.length-20);

			byte[] cipmsghash = sha1_hash(msgvalue);
			//If the hash value that was parsed from the cipher message and the hash value computed from the recieved message is equal, write the message to the file.
			if(Arrays.equals(cipmsghash, hashvalue)){
				System.out.println("Same");
				out_file.write(msgvalue);
				out_file.close();
			}else{
				System.out.println("Not same");
				
			}






        }catch (Exception e){
			System.out.println(e);
        }finally{
            if (in_file != null){
				in_file.close();
			}
			if(out_file != null){
				out_file.close();
			}
        }



    }

    public static byte[] sha1_hash(byte[] input_data) throws Exception{
		byte[] hashval = null;
		try{
			//create message digest object
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			
			//make message digest
			hashval = sha1.digest(input_data);
		}
		catch(NoSuchAlgorithmException nsae){
			System.out.println(nsae);
		}
		return hashval;
    }
    
    public static String aes_decrypt(byte[] data_in) throws Exception{
		byte[] decrypted = null;
		String dec_str = null;
		try{
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

			//do decryption
			decrypted = sec_cipher.doFinal(data_in);

			//convert to string
			dec_str = new String(decrypted);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return dec_str;
	}
	
	//Does same thing as aes_decrypt_byte but instead it returns byte array
	public static byte[] aes_decrypt_byte(byte[] data_in) throws Exception{
		byte[] decrypted = null;
		try{
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec);

			//do decryption
			decrypted = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return decrypted;
    }
    

    public static byte[] generateDSASig(byte[] hash){
		byte[] ret = null;

		try{
			keypairgen = KeyPairGenerator.getInstance("DSA");
			secRan = SecureRandom.getInstance("SHA1PRNG");
			keypairgen.initialize(1024, secRan);
			keypair = keypairgen.generateKeyPair();

			//get private and public keys
			private_key = (DSAPrivateKey) keypair.getPrivate();
			public_key = (DSAPublicKey) keypair.getPublic();

			//make DSA object
			dsa_sig = Signature.getInstance("SHA/DSA");
			dsa_sig.initSign(private_key);
			dsa_sig.update(hash);
			ret = dsa_sig.sign();
		}
		catch(Exception e){
			System.out.println(e);
		}

		return ret;		
	}

	public static boolean verifyDSASig(byte[] signature, byte[] hash){
		boolean verified = false;

		try{
			//put signature in Verify mode
			dsa_sig.initVerify(public_key);
			
			//load the data to verify
			dsa_sig.update(hash);

			//get verification boolean
			verified = dsa_sig.verify(signature);
		}
		catch(Exception e){
			System.out.println(e);
        }
		return verified;
	}


    /*
     * Converts a byte array to hex string
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        } 
        return buf.toString();
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }




}