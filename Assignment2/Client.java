import java.io.*;
import java.net.*;
import javax.crypto.spec.*;
//import com.sun.corba.se.impl.ior.ByteBuffer;
import java.nio.ByteBuffer;


/**
 * Client program.  Connects to the server and sends text accross.
 */

public class Client 
{
    private Socket sock;  //Socket to communicate with.
	static FileInputStream in_file = null;
	static byte[] out_file = null;
	static byte[] seed = null;
    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
    public static void main (String [] args)
    {
		if (args.length < 5) {
			System.out.println ("Usage: java Client hostname port# sourceFile destFile seed");
			System.out.println ("hostname is a string identifying your server");
			System.out.println ("port is a positive integer identifying the port to connect to the server");
			return;
		}
		try{
			in_file = new FileInputStream(args[2]);
			out_file = args[3].getBytes();
			seed = args[4].getBytes();
		}
		catch (Exception e){
			System.out.print(e);
			return;
		}
		try {
			Client c = new Client (args[0], Integer.parseInt(args[1]));
		}
		catch (NumberFormatException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("Second argument was not a port number");
			return;
		}
    }
	
    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port)
    {
		/* Allows us to get input from the keyboard. */
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		DataOutputStream fromcliout;
		String userinput;
		PrintWriter out;
		DataInputStream inCli;
		
			
		/* Try to connect to the specified host on the specified port. */
		try {
			sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
			System.out.println ("Usage: java Client hostname port#");
			System.out.println ("First argument is not a valid hostname");
			return;
		}
		catch (IOException e) {
			System.out.println ("Could not connect to " + ipaddress + ".");
			return;
		}
			
		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);
			
		try {
			out = new PrintWriter(sock.getOutputStream());
		}
		catch (IOException e) {
			System.out.println ("Could not create output stream.");
			return;
		}

		try {
			fromcliout = new DataOutputStream(sock.getOutputStream());
			inCli = new DataInputStream(sock.getInputStream());
		}catch (Exception e){
			System.out.println(e);
			return;
		}
		
			
		/* Wait for the user to type stuff. */
		try {
			ByteBuffer bb = ByteBuffer.allocate(4);
			byte[] filemsg = new byte[in_file.available()];
			int read_bytes = in_file.read(filemsg);
			bb.putInt(read_bytes);
			byte[] lengthbyte = bb.array();
			// compute key:  1st 16 bytes of SHA-1 hash of seed
			SecretKeySpec key = CryptoUtilities.key_from_seed(seed);

			// append HMAC-SHA-1 message digest
			
			byte[] hashed_file_msg = CryptoUtilities.append_hash(filemsg,key);

			// do AES encryption
			byte[] aes_ciphertext_file = CryptoUtilities.encrypt(hashed_file_msg,key);

			byte[] hashed_len = CryptoUtilities.append_hash(lengthbyte, key);

			byte[] ciph_len = CryptoUtilities.encrypt(hashed_len, key);

			byte[] hashed_name = CryptoUtilities.append_hash(out_file, key);

			byte[] ciph_name = CryptoUtilities.encrypt(hashed_name, key);

			//System.out.println(read_bytes);
			fromcliout.writeInt(ciph_name.length);
			fromcliout.write(ciph_name);
			int response = inCli.readInt();
			if(response == 1){
				fromcliout.writeInt(aes_ciphertext_file.length);
				fromcliout.write(aes_ciphertext_file);

				response = inCli.readInt();
				if (response == 1){
					fromcliout.writeInt(ciph_len.length);
					fromcliout.write(ciph_len);

					response = inCli.readInt();

					if(response == 1){
						System.out.println("Successfully transfered file.");
					}else{
						System.out.println("Failed to transfered file");
					}
				} else{
					System.out.println("Failed to transfered file");
				}
				
				
			}else{
				System.out.println("Failed to transfered file");
			}

			System.out.println ("Client exiting.");
			stdIn.close ();
			out.close ();
			sock.close();
			return;
			
		} catch (IOException e) {
			System.out.println ("Could not read from input.");
			return;
		} catch (Exception e){
			System.out.println(e);
			return;
		}		
    }
}