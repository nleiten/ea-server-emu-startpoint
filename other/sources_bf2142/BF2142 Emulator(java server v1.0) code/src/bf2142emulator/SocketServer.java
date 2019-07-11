package bf2142emulator;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.net.ssl.SSLServerSocketFactory;

/**
 *
 * @author Freek
 */
public class SocketServer {

    private ServerSocket server                     = null;
    private static ArrayList<ClientWorker> clients  = null;

    public SocketServer(int port)
    {
        System.setProperty("javax.net.ssl.keyStore", "eaTest");
        System.setProperty("javax.net.ssl.keyStorePassword", "123456");

        try {
            //Open the 4321 port
            server      = SSLServerSocketFactory.getDefault().createServerSocket(port);
            System.out.println("Created socket server on port "+port+".");
        } catch(IOException e) {
            System.out.println("Could not create socket! Port "+port+" in use?");
            System.exit(-1);
        }

        //Create the clients
        clients         = new ArrayList<ClientWorker>();
    }

    public void run()
    {
        while(true)
        {
            try {
                //Wait for a new connection
                Socket client = server.accept();

                //Create the client worker and start the thread
                ClientWorker w      = new ClientWorker(client);
                Thread t            = new Thread(w);
                t.start();

            } catch(IOException e) {
                System.out.println("Could not accept socket connection!");
            }
        }

    }

    //Get the current connected clients
    public static synchronized ArrayList<ClientWorker> getClients()
    {
        return (ArrayList<ClientWorker>)clients.clone();
    }

    //Add a client to the client list
    public static synchronized void addClient(ClientWorker worker)
    {
        clients.add(worker);
    }

    //Remove a client from the client list
    public static synchronized void removeClient(ClientWorker worker)
    {
        clients.remove(worker);
    }
}
