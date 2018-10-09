
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;



public class secureFile{
    private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;

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

            secRan = SecureRandom.getInstance("SHA1PRNG");
            secRan.setSeed(seedByte);

            System.out.println("Seedbyte: " + seedByte);
            
            byte[] msg = new byte[in_file.available()];
			read_bytes = in_file.read(msg);

            sha_hash = sha1_hash(msg);

			//print out hash in hex
            System.out.println("SHA-1 Hash: " + toHexString(sha_hash));
            
            //encrypt file with AES
			//key setup - generate 128 bit key
			key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(128,secRan);
			sec_key = key_gen.generateKey();

			//get key material in raw form
			raw = sec_key.getEncoded();
			sec_key_spec = new SecretKeySpec(raw, "AES");

            //System.out.println("Key: " + sec_key_spec);
			//create the cipher object that uses AES as the algorithm
			sec_cipher = Cipher.getInstance("AES");	

			//do AES encryption
            aes_ciphertext = aes_encrypt(msg);
			//System.out.println("encrypted file: " + toHexString(aes_ciphertext));
			out_file.write(aes_ciphertext);
			out_file.close();

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

        System.out.println("secureFile worked");
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
    
    public static byte[] aes_encrypt(byte[] data_in) throws Exception{
		byte[] out_bytes = null;
		try{
			//set cipher object to encrypt mode
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec);

			//create ciphertext
			out_bytes = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return out_bytes;
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
    public static int stringToSeed(String input){
        int seed = 0;
        for(int i = 0; i < input.length();i++){
            seed += (int)input.charAt(i);
        }
        return seed;
    }
    */
}