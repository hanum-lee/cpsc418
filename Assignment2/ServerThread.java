import java.net.*;
import java.io.*;
import javax.crypto.spec.*;
import java.nio.ByteBuffer;

/**
 * Thread to deal with clients who connect to Server.  Put what you want the
 * thread to do in it's run() method.
 */

public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
	private int idnum;  //The client's id number.
	private SecretKeySpec key;
	private boolean debug;

    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id, byte[] seedbyte, boolean destatus)
    {
		parent = p;
		sock = s;
		idnum = id;
		key = CryptoUtilities.key_from_seed(seedbyte);
		debug = destatus;
		//System.out.println("Seed:" + seed);
    }
	
    /**
     * Getter for id number.
     * @return ID Number
     */
    public int getID ()
    {
		return idnum;
    }
	
    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
	return sock;
    }
	
    /**
     * This is what the thread does as it executes.  Listens on the socket
     * for incoming data and then echos it to the screen.  A client can also
     * ask to be disconnected with "exit" or to shutdown the server with "die".
     */
    public void run ()
    {
		DataInputStream inSer = null;
		byte[] temp = null;
		int msglen;
		DataOutputStream fromSer = null;
		FileOutputStream out_file = null;
		int status = 1;
		FileInputStream in_file = null;
		try{
			inSer = new DataInputStream(sock.getInputStream());
			fromSer = new DataOutputStream(sock.getOutputStream());
		}
		catch (Exception e){
			System.out.println(e);
		}
		
		/* Try to read from the socket */
		try {
			msglen = inSer.readInt();
			
		}
		catch (IOException e) {
			if (parent.getFlag())
			{
				System.out.println ("shutting down.");
				return;
			}
			return;
		}
		/* See if we've recieved something */
		if(msglen > 0){
			temp = new byte[msglen];
			try{
				inSer.readFully(temp, 0, msglen);
			}catch (Exception e){
				System.out.println("Reading:" + e);
				return;
			}
			
		}

		byte[] hashed_name = CryptoUtilities.decrypt(temp,key);
		if (CryptoUtilities.verify_hash(hashed_name,key)){
			byte[] decrName = CryptoUtilities.extract_message(hashed_name);
			String fileName = null;
			try{
				fileName = new String(decrName, "UTF-8");
			} catch (Exception e){
				System.out.println("Showing: "+e);
				return;
			}

			try{
				if(debug){
					System.out.println("Client " + idnum + ": " + "Destination ACK: " + status);
				}
				fromSer.writeInt(status);
			}catch (Exception e){
				
			}
			
			try {
				msglen = inSer.readInt();
			}
			catch (IOException e) {
				if (parent.getFlag())
				{
					System.out.println ("shutting down.");
					return;
				}
				return;
			}
			/* See if we've recieved something */
			
			if(msglen > 0){
				temp = new byte[msglen];
				try{
					inSer.readFully(temp, 0, msglen);
				}catch (Exception e){
					System.out.println("Reading:" + e);
					return;
				}
				
			}

			byte[] hashed_file = CryptoUtilities.decrypt(temp,key);
			if (CryptoUtilities.verify_hash(hashed_file,key)){
				byte[] decrfile = CryptoUtilities.extract_message(hashed_file);
				String mess = null;
				try{
					mess = new String(decrfile, "UTF-8");
				} catch (Exception e){
					System.out.println("Showing: "+e);
					return;
				}
				//System.out.println("File:" + mess);

				try{
					if(debug){
						System.out.println("Client " + idnum + ": " + "File ACK: " + status);
					}
					fromSer.writeInt(status);
				}catch (Exception e){
					
				}
				
				try {
					msglen = inSer.readInt();
				}
				catch (IOException e) {
					if (parent.getFlag())
					{
						System.out.println ("shutting down.");
						return;
					}
					return;
				}
				/* See if we've recieved something */
				
				if(msglen > 0){
					temp = new byte[msglen];
					try{
						inSer.readFully(temp, 0, msglen);
					}catch (Exception e){
						System.out.println("Reading:" + e);
						return;
					}
					
				}
				byte[] hashed_len = CryptoUtilities.decrypt(temp,key);
				if (CryptoUtilities.verify_hash(hashed_len,key)){
					byte[] decrlen = CryptoUtilities.extract_message(hashed_len);
					int delen = ByteBuffer.wrap(decrlen).getInt();
					//System.out.println("lenght:" + delen);
					
					try{
						out_file = new FileOutputStream(fileName);
						out_file.write(decrfile);
						out_file.close();
						in_file = new FileInputStream(fileName);
						byte[] msg = new byte[in_file.available()];
						int read_bytes = in_file.read(msg);
						if(read_bytes != delen){
							status = 0;
						}

					}catch (Exception e){
						status = 0;
					}


				}else {
					status = 0;
				}

				
			}else{
				status = 0;
			}
			
		}else{
			status = 0;
		}
		try{
			if(debug){
				System.out.println("Client " + idnum + ": " + "Final ACK: " + status);
			}
			fromSer.writeInt(status);
		}catch (Exception e){
			System.out.println(e);
			return;
		}

			parent.killall();
			
			try{
				sock.close();
				inSer.close();
				fromSer.close();

			}catch (Exception e){
				System.out.println("Closing:" + e);
				return;
			}
		
			return;
    }
}