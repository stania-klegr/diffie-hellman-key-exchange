import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.math.BigInteger;

//Stania Klegr

class client {
    public static void main(String args[])
    {
    	//checks that there is the correct number of args and if there isant prints the correct usage
        if(args.length != 3)
    	{
    		System.out.println("Usage: <domain> <port> <private key>");
    		System.exit(0);
    	}
		try
		{
			String domain = args[0];
            int port = Integer.parseInt(args[1]);

			//creates a inetAdderss object from the domain name
			InetAddress IP = InetAddress.getByName(domain);

			//creates new socket with the specified address and port
			Socket me = new Socket(IP, port);

            ObjectOutputStream oos = new ObjectOutputStream(me.getOutputStream());
            DataOutputStream dOut = new DataOutputStream(me.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(me.getInputStream());

            //recive the public and client keys
            BigInteger p = (BigInteger) ois.readObject();
            System.out.println("recived p/n:           " + p);

            BigInteger g = (BigInteger) ois.readObject();
            System.out.println("recived g:             " + g);

            BigInteger serverKey = (BigInteger) ois.readObject();
            System.out.println("recived server key:    " + serverKey);

            //compute our key
            BigInteger priveKey = new BigInteger(args[2]);

            BigInteger clientKey = g.modPow(priveKey, p);
            // long clientKey = (long)Math.pow(g, priveKey) % p;

            oos.writeObject(clientKey);
            oos.flush();
            System.out.println("sent clientKey:\t" + clientKey);

            //compute the shared key
            BigInteger shared = serverKey.modPow(priveKey, p);
            System.out.println("shared key: " + shared);

            ReciverWorker reciver = new ReciverWorker(me, shared);
			reciver.start();

            //get bytes from the long
            byte[] key;

            key = shared.toByteArray();

            String msg;
            //loop forever and send anything typed into the console
			while(true)
			{
				//get the line from the console
				msg = System.console().readLine();

                byte[] message = msg.getBytes();

                message = encrypt(message, key);

                dOut.writeInt(message.length); // write length of the message
                dOut.write(message);           // write the message
			}
		}
		catch(Exception e)
		{
            System.out.println(e);
		}
    }

    private static byte[] encrypt(byte[] str, byte[] key) {

        byte[] output = new byte[str.length];

        for(int i = 0; i < str.length; i++) {
            output[i] = (byte)(str[i] ^ key[i % key.length]);
        }
        return output;
    }
}

class ReciverWorker extends Thread{

	Socket me;
    BigInteger shared;
	//constructor
	public ReciverWorker(Socket me, BigInteger shared)
	{
		this.me = me;
        this.shared = shared;
	}

    public void run()
    {
    	System.out.println("running the session");
		try
		{
            DataInputStream dIn = new DataInputStream(me.getInputStream());

            //get bytes from the long
            byte[] key;

            key = shared.toByteArray();

			//loops forever and prints any recived packet to the console
			while(true)
			{
                //reads and prints the response from the server
                int length = dIn.readInt();// read length of incoming message
                if(length>0) {
                    byte[] message = new byte[length];
                    dIn.readFully(message, 0, message.length); // read the message

                    String s = new String(message);
                    System.out.println("un-decrypted: " + s);

                    message = decrypt(message, key);

                    s = new String(message);
                    System.out.println("decrypted:    " + s);
                }
			}
		}
		catch(Exception ex)
		{
			System.out.println("Disconnected: " + ex);
		}
    }

    //decrypts the string with the supplied key using an xor bassed cipher
    private static byte[] decrypt(byte[] str, byte[] key) {

        byte[] output = new byte[str.length];

        for(int i = 0; i < str.length; i++) {
            // convert to ints and xor
            int one = (int)str[i];
            int two = (int)key[i % key.length];
            int xor = one ^ two;

            byte b = (byte)(0xff & xor);

            output[i] = b;
        }
        return output;
    }
}
