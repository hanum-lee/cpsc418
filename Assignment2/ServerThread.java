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

    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id, byte[] seedbyte)
    {
		parent = p;
		sock = s;
		idnum = id;
		key = CryptoUtilities.key_from_seed(seedbyte);
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
		BufferedReader in = null;
		String incoming = null;
		DataInputStream inSer = null;
		byte[] inmsg = new byte[2048];
		byte[] temp = null;
		int msglen;
		DataOutputStream fromSer = null;
		FileOutputStream out_file = null;
		int status = 1;

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
		System.out.println("Working?");
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

			System.out.println ("Client " + idnum + ": " + fileName + "Length: " + temp.length);

			
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
				System.out.println("File:" + mess);

				
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
					System.out.println("lenght:" + delen);
					
					try{
						out_file = new FileOutputStream(fileName);
						//int length = out_file.read();
						//System.out.println("File Length: " + length);
						out_file.write(decrfile);
						out_file.close();
						

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
			fromSer.writeInt(status);
		}catch (Exception e){
			System.out.println(e);
			return;
		}


		//System.out.println("Message: " + mess);
		//while (inmsg != null)
		//	{
			/* If the client has sent "exit", instruct the server to
			* remove this thread from the vector of active connections.
			* Then close the socket and exit.
			*/
		/*		if (incoming.compareTo("exit") == 0){
						parent.kill (this);
						try {
							in.close ();
							sock.close ();
						}
						catch (IOException e)
							{}
						return;
				}*/
				
			/* If the client has sent "die", instruct the server to
			* signal all threads to shutdown, then exit.
			*/
			/*	else if (incoming.compareTo("die") == 0)
					{
					parent.killall ();
					return;
					}	
			*/	
			/* Otherwise, just echo what was recieved. */
			//	String[] splited = incoming.split("\\s+");
		//		System.out.println ("Client " + idnum + ": " + temp);
				//msgs[counter] = inmsg;
				
				
			/* Try to get the next line.  If an IOException occurs it is
			* probably because another client told the server to shutdown,
			* the server has closed this thread's socket and is signalling
			* for the thread to shutdown using the shutdown flag.
			*//*
				try {
					incoming = in.readLine ();
					inmsg = inSer.readAllBytes();
					inSer.readFully(temp);
					
				}
				catch (IOException e) {
					if (parent.getFlag())
					{
						System.out.println ("shutting down.");
						return;
					}
					else
					{
						System.out.println ("IO Error.");
						return;
					}
				}
			}*/
			parent.killall();
			
			try{
				sock.close();
				inSer.close();
			}catch (Exception e){
				System.out.println("Closing:" + e);
				return;
			}
		
			return;
    }
}