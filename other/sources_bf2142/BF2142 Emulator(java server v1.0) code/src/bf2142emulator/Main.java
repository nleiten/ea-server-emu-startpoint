package bf2142emulator;

/**
 *
 * @author Freek
 */
public class Main {

    public static SocketServer socketServer;
    public static Database db;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        //Create the socketServer
	socketServer		= new SocketServer(18300); //BF2142: 18390
        db                      = new Database("127.0.0.1", "root", "325v43t5f4tvg5ft5", "bf2142");

	//Run the socket server
	socketServer.run();
    }

}
