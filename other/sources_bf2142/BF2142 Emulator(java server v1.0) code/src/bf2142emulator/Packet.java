package bf2142emulator;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 *
 * @author Freek
 */
public class Packet {

    private String type;
    private LinkedHashMap<String,String> data;
    private int counter;

    public Packet(String type, int counter)
    {
        this.type       = type;
        this.counter    = counter;
        this.data       = new LinkedHashMap<String,String>();
    }

    public Packet(DataInputStream in) throws IOException
    {
        byte[] header       = new byte[12];
        in.readFully(header);

        this.type           = new String(header, 0, 4);
        this.counter        = decodeHeader(header, 4, 4);
        int size            = decodeHeader(header, 8, 4);

        if(size < 0)
            throw new IOException("Header: Size mismatch!");

        byte[] data         = new byte[size-12];
        in.readFully(data);

        this.data           = formatData(new String(data));
    }

    private LinkedHashMap<String,String> formatData(String data)
    {
        LinkedHashMap<String,String> ret      = new LinkedHashMap<String,String>();

        String[] lines      = data.split("\\n");
        for(String line : lines)
        {
            String[] l   = line.split("=");

            if(l.length == 2)
                ret.put(l[0], l[1]);
            else if(l.length == 1 && l[0].length() > 0)
                ret.put(l[0], "");
        }

        return ret;
    }

    private String getData()
    {
        String ret      = new String();

        for(Map.Entry<String, String> e : data.entrySet())
            ret         += e.getKey() + "=" + e.getValue() + "\n";

        return ret;
    }

    private int decodeHeader(byte[] input, int offset, int size)
    {
        int ret     = 0;
        for(int i = offset; i < size+offset; i++)
            ret     |= ((input[i] & 0xFF) << ((size - 1 - i) << 3)); // big

        return ret;
    }

    private byte[] encodeHeader(int input, int offset, int size)
    {
        byte[] ret      = new byte[size];
        for(int i = offset; i < size+offset; i++)
            ret[i]     = (byte) (input >> ((size - 1 - i) << 3)); // big

        return ret;
    }

    public void send(DataOutputStream out) throws IOException
    {
        out.write(type.getBytes());
        out.write(encodeHeader(counter, 0, 4), 0, 4);
        out.write(encodeHeader(getSize(), 0, 4), 0, 4);
        out.write(getData().getBytes());
        out.flush();
    }

    public String getType()
    {
        return type;
    }

    public int getCounter()
    {
        return counter;
    }

    public int getSize()
    {
        return getData().getBytes().length+12;
    }

    public String get(String name)
    {
        return data.get(name);
    }

    public void set(String name, String var)
    {       
        data.put(name, var);
    }

    public void set(String name, int var)
    {
        set(name, String.valueOf(var));
    }

    public void remove(String name)
    {
        data.remove(name);
    }

    public String toString()
    {
        return "<Packet[type: "+type+", counter: "+counter+", data: "+getData()+"]>";
    }
}
