import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.math.BigInteger;

class server {
    public static void main(String args[])
    {
        if(args.length != 3){
            System.out.println("Usage: <p> <g> <private key>");
            System.exit(0);
        }

        try
        {
            BigInteger p = new BigInteger(args[0]);
            BigInteger g = new BigInteger(args[1]);
            BigInteger priveKey = new BigInteger(args[2]);

            //create a new server socket
            ServerSocket echoServer = new ServerSocket(41875);
            System.out.println(echoServer.getLocalPort());

            //wait for a connection
            System.out.println("server is waiting for the the connection...");
            Socket client = echoServer.accept();
            System.out.println("Here comes a request.");

            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            DataOutputStream dOut = new DataOutputStream(client.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

            //compute our key
            BigInteger serverKey = g.modPow(priveKey, p);

            //send the public numbers and our key
            oos.writeObject(p);
            oos.flush();
            System.out.println("sent p/n:           " + p);

            oos.writeObject(g);
            oos.flush();
            System.out.println("sent g:             " + g);

            oos.writeObject(serverKey);
            oos.flush();
            System.out.println("sent serverKey:     " + serverKey);

            //recive the clients key
            BigInteger clientKey = (BigInteger) ois.readObject();
            System.out.println("recived client key: " + clientKey);

            //compute the shared key
            BigInteger shared = clientKey.modPow(priveKey, p);
            System.out.println("shared key: " + shared);

            ReciverWorker reciver = new ReciverWorker(client, shared);
            reciver.start();

            // //get bytes from the long
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

                dOut.writeInt(message.length);
                dOut.write(message);           // write the message
			}
        }
        catch(Exception e)
        {
            System.out.println("Only numerical keys are allowed. " + e.getMessage());
        }
    }

    //encrypts the string with the supplied key using an xor bassed cipher
    private static byte[] encrypt(byte[] str, byte[] key) {

        byte[] output = new byte[str.length];

        for(int i = 0; i < str.length; i++) {
            output[i] = (byte)(str[i] ^ key[i % key.length]);
        }
        return output;
    }
}
