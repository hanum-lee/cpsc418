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
		
		String userinput;
		PrintWriter out;
		
			
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

			out.print(ciph_name);
			out.print(aes_ciphertext_file);
			out.print(ciph_len);

			
			while ((userinput = stdIn.readLine()) != null) {
				/* Echo it to the screen. */
				//out.println(userinput);
						
				/* Tricky bit.  Since Java does short circuiting of logical 
				* expressions, we need to checkerror to be first so it is always 
				* executes.  Check error flushes the outputstream, which we need
				* to do every time after the user types something, otherwise, 
				* Java will wait for the send buffer to fill up before actually 
				* sending anything.  See PrintWriter.flush().  If checkerror
				* has reported an error, that means the last packet was not 
				* delivered and the server has disconnected, probably because 
				* another client has told it to shutdown.  Then we check to see
				* if the user has exitted or asked the server to shutdown.  In 
				* any of these cases we close our streams and exit.
				*/
				if ((out.checkError()) || (userinput.compareTo("exit") == 0) || (userinput.compareTo("die") == 0)) {
					System.out.println ("Client exiting.");
					stdIn.close ();
					out.close ();
					sock.close();
					return;
				}
			}
		} catch (IOException e) {
			System.out.println ("Could not read from input.");
			return;
		} catch (Exception e){
			System.out.println(e);
			return;
		}		
    }
}