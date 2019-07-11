package bf2142emulator;

import java.io.DataOutputStream;

/**
 *
 * @author Freek
 */
public class PingWorker extends Thread {
    DataOutputStream out;

    public PingWorker(DataOutputStream out)
    {
        this.out        = out;
    }

    public void run() {
        try {
            while(true)
            {
                this.sleep(120000);
                Packet sendPacket   = new Packet("PING", 0x80000000);
                sendPacket.set("TXN", "PING");
                sendPacket.send(out);
            }
        } catch (Exception ex) {
        }
    }
}
