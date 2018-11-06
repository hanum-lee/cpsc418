
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;


public class Secure{
    private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
    private static Cipher sec_cipher = null;
    private static byte[] seedByte = null;
    private static SecureRandom seedRan = null;
    private static int seedNum = null;
    private static String fileIn = null;


    public Secure(String[] args) throws Exception{
        FileInputStream in_file = null;
        byte[] sha_hash = null;
		byte[] hmac_hash = null;
		byte[] aes_ciphertext = null;
		byte[] sig = null;
		String decrypted_str = new String();
		int read_bytes = 0;
        boolean verify = false;
        try{
            in_file = new FileInputStream(args[0]);
            seedByte = args[2].getBytes();

        }catch (Exception e){

        }finally{
            if (in_file != null){
				in_file.close();
			}
        }


    }

    public byte[] encryptFile(String[] args) throws Exception {

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
}