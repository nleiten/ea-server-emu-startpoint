package bf2142emulator;

import java.net.*;
import java.io.*;
import java.sql.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

/**
 *
 * @author Freek
 */
public class ClientWorker implements Runnable {

    private static  DateFormat packetDateFormat     = new SimpleDateFormat("MMM-dd-yyyy HH%3'a'mm%3'a'ss zzz");
    private         Socket client;
    private         int packetCounter               = 1;

    private         int userId                      = -1;
    private         int personaId                   = -1;
    private         int profileId                   = -1;

    public ClientWorker(Socket client)
    {
        this.client     = client;
    }
    
    private void println(String str)
    {
        DateFormat dateFormat   = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        System.out.println("["+dateFormat.format(new Date())+" | "+getAddressPort()+"] "+str);
    }

    private static String generateString(int length)
    {
        Random rng              = new Random();
        String characters       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char[] text = new char[length];
        for (int i = 0; i < length; i++)
        {
            text[i] = characters.charAt(rng.nextInt(characters.length()));
        }
        return new String(text);
    }

    public String getAddressPort()
    {
        return client.getInetAddress().getHostAddress()+":"+client.getPort();
    }

    public void run()
    {
        DataInputStream in    = null;
        DataOutputStream out  = null;

        try {
            in      = new DataInputStream(client.getInputStream());
            out     = new DataOutputStream(client.getOutputStream());
        } catch(IOException e) {
            println("Could not create in- or output buffer!");
            return;
        }

        //Show the connect message
        println("Client connected!");

        //Add the client to the list
        SocketServer.addClient(this);

        //Create the ping thread
        Thread pingThread       = new PingWorker(out);
        pingThread.start();

        while(true) {
            try {
                //Receive packet
                Packet recievePacket        = new Packet(in);
                println("Recieve packet: "+recievePacket.toString()); //DEBUG SHIT

                String txn      = recievePacket.get("TXN");
                if(recievePacket.getType().equals("fsys"))
                {
                    if(txn == null)
                        break;
                    else if(txn.equals("Hello"))
                    {
                        //Send hello back with theater information
                        Packet sendPacket   = new Packet("fsys", 0x80000000|packetCounter++);
                        sendPacket.set("TXN", "Hello");
                        sendPacket.set("domainPartition.domain", "eagames");
                        sendPacket.set("messengerPort", 1305);
                        sendPacket.set("domainPartition.subDomain", "battlefield2142-2006"); //BF2142 battlefield2142-2006
                        sendPacket.set("activityTimeoutSecs", 0);
                        sendPacket.set("curTime", "\""+packetDateFormat.format(new Date())+"\"");
                        sendPacket.set("theaterIp", "0.0.0.0");
                        sendPacket.set("theaterPort", 0);
                        sendPacket.send(out);
                        println("Send packet: "+sendPacket.toString()); //DEBUG SHIT

                        sendPacket   = new Packet("fsys", 0x80000000);
                        sendPacket.set("TXN", "MemCheck");
                        sendPacket.set("memcheck.[]", 0);
                        sendPacket.set("type", 0);
                        sendPacket.set("salt", (int)new Date().getTime());
                        sendPacket.send(out);
                        println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                    }
                    else if(txn.equals("MemCheck"))
                    {
                        //Ignore
                    }
                    else if(txn.equals("Goodbye"))
                    {
                        //Client says goodbye

                        break;
                    }
                    else
                        break;
                }
                else if(recievePacket.getType().equals("acct"))
                {
                    if(txn == null)
                        break;
                    else if(txn.equals("Login"))
                    {
                        //Check login info
                        String username     = recievePacket.get("name");
                        String password     = recievePacket.get("password");
                        ResultSet res       = null;

                        if(username != null && password != null)
                            res       = Main.db.query("SELECT `user_id`,`user_displayName`,`profile_id` FROM `users` WHERE `user_nuid`=? AND `user_password`=?", username, password);

                        if(res != null && res.next()) {
                            this.profileId      = res.getInt("profile_id");
                            this.userId         = res.getInt("user_id");

                            String lkey         = ClientWorker.generateString(30)+".";
                            Main.db.execute("UPDATE `users` SET `user_online`='1', `user_lastLogin`=CURRENT_TIMESTAMP(), `user_lkey`=? WHERE `user_id`=?", lkey, ""+this.userId);

                            Packet sendPacket = new Packet("acct", 0x80000000 | packetCounter++);
                            sendPacket.set("TXN", "Login");
                            sendPacket.set("lkey", lkey);
                            sendPacket.set("displayName", res.getString("user_displayName"));
                            sendPacket.set("profileId", this.profileId);
                            sendPacket.set("userId", this.userId);

                            sendPacket.send(out);
                            println("Send packet: " + sendPacket.toString()); //DEBUG SHIT
                        }
                        else
                        {
                            Packet sendPacket = new Packet("acct", 0x80000000 | packetCounter++);
                            sendPacket.set("TXN", "Login");
                            sendPacket.set("localizedMessage", "\"The username or password is incorrect\"");
                            sendPacket.set("errorCode", "122");

                            sendPacket.send(out);
                            println("Send packet: " + sendPacket.toString()); //DEBUG SHIT
                        }

                    }
                    else if(txn.equals("GetSubAccounts"))
                    {
                        //Get the personas
                        ResultSet res       = null;
                        int counter         = 0;

                        if(this.userId != -1)
                            res       = Main.db.query("SELECT `persona_name` FROM `personas` WHERE `user_id`=?", ""+this.userId);

                        Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                        sendPacket.set("TXN", "GetSubAccounts");

                        while(res != null && res.next())
                        {
                            sendPacket.set("subAccounts."+counter, res.getString("persona_name"));
                            counter++;
                        }
                        
			sendPacket.set("subAccounts.[]", counter);
                        sendPacket.send(out);
                        println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                    }
                    else if(txn.equals("LoginSubAccount"))
                    {
                        //Check the persona login
                        ResultSet res       = null;
                        if(this.userId != -1)
                            res       = Main.db.query("SELECT `persona_id` FROM `personas` WHERE `user_id`=? AND `persona_name`=?", ""+this.userId, recievePacket.get("name"));

                        if(res != null && res.next())
                        {
                            this.personaId      = res.getInt("persona_id");

                            String lkey         = ClientWorker.generateString(30)+".";
                            Main.db.execute("UPDATE `personas` SET `persona_online`='1', `persona_lastLogin`=CURRENT_TIMESTAMP(), `persona_lkey`=? WHERE `persona_id`=?", lkey, ""+this.personaId);

                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "LoginSubAccount");
                            sendPacket.set("lkey", "rQF69AzBlax3CF3EDNhm3soLBPh71Y.");
                            sendPacket.set("profileId", this.profileId);
                            sendPacket.set("userId", this.userId);
                            sendPacket.send(out);
                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "LoginSubAccount");
                            sendPacket.set("localizedMessage", "\"ERROR 0x00002 Please contact server admin at Gh05n3t.net!\"");
                            sendPacket.set("errorCode", "122");
                            sendPacket.send(out);
                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                    }
                    else if(txn.equals("GetAccount"))
                    {
                        Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                        sendPacket.set("TXN", "GetAccount");
			sendPacket.set("countryDesc", "\"United States of America\"");
			sendPacket.set("thirdPartyMailFlag", "1");
			sendPacket.set("dobMonth", "6");
			sendPacket.set("dobYear", "1989");
                        sendPacket.set("profileID", "ea4d5sdf4\\x00");
                        sendPacket.set("email", "bf@gh05tn3t.net");
			sendPacket.set("name", "Gh05tn3t");
                        sendPacket.set("userId", "2dh3udh5h\\x00");
			sendPacket.set("zipCode", "97090");
			sendPacket.set("gender", "U");
			sendPacket.set("dobDay", "2");
			sendPacket.set("eaMailFlag", "1");

                        sendPacket.send(out);
                        println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                    }
                    else if(txn.equals("GameSpyPreAuth"))
                    {
                        String ticket       = "O%%3d%%3d%%3d"+ClientWorker.generateString(10);

                        if(this.personaId != -1)
                            Main.db.execute("UPDATE `personas` SET `authtoken`=? WHERE `persona_id`=?", ticket, ""+this.personaId);

                        Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                        sendPacket.set("TXN", "GameSpyPreAuth");
                        sendPacket.set("challenge", "test");
                        sendPacket.set("ticket", ticket);

                        sendPacket.send(out);
                        println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                    }
                    else
                        break;
                }
                else if(recievePacket.getType().equals("subs"))
                {
                    if(txn == null)
                        break;
                    else if(txn.equals("GetEntitlementByBundle"))
                    {
                        String bundleId     = recievePacket.get("bundleId");

                        if(bundleId == null)
                            break;
                        else if(bundleId.equals("REG-PC-BF2142-UNLOCK-1"))
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "GetEntitlementByBundle");
                            sendPacket.set("localizedMessage", "\"The customer has never had entitlement for this bundle.\"");
                            sendPacket.set("errorContainer.[]", "0");
                            sendPacket.set("errorCode", "3012");
                            sendPacket.send(out);

                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else if(bundleId.equals("REG-PC-BF2142-UNLOCK-2"))
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "GetEntitlementByBundle");
                            sendPacket.set("localizedMessage", "\"The customer has never had entitlement for this bundle.\"");
                            sendPacket.set("errorContainer.[]", "0");
                            sendPacket.set("errorCode", "3012");
                            sendPacket.send(out);

                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else if(bundleId.equals("REG-PC-BF2142-UNLOCK-3"))
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "GetEntitlementByBundle");
                            sendPacket.set("localizedMessage", "\"The customer has never had entitlement for this bundle.\"");
                            sendPacket.set("errorContainer.[]", "0");
                            sendPacket.set("errorCode", "3012");
                            sendPacket.send(out);

                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else
                            break;
                    }
                    else
                        break;
                }
                else if(recievePacket.getType().equals("dobj"))
                {
                    if(txn == null)
                        break;
                    else if(txn.equals("GetObjectInventory"))
                    {
                        String domainId     = recievePacket.get("domainId");

                        if(domainId == null)
                            break;
                        else if(domainId.equals("eagames"))
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "GetObjectInventory");
                            sendPacket.set("entitlements.[]", "0");
                            sendPacket.send(out);

                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else if(domainId.equals("cqc"))
                        {
                            Packet sendPacket   = new Packet("acct", 0x80000000|packetCounter++);
                            sendPacket.set("TXN", "GetObjectInventory");
                            sendPacket.set("entitlements.[]", "0");
                            sendPacket.send(out);

                            println("Send packet: "+sendPacket.toString()); //DEBUG SHIT
                        }
                        else break;
                    }
                    else
                        break;
                }


            } catch (SQLException ex) {
                println(ex.getMessage());
                break;
            } catch (IOException ex) {
                println(ex.getMessage());
                break;
            }
        }

        //Close the socket
        try {
            client.close();
        } catch (Exception e) {
            println("Could not close socket connection! Already closed?");
        }

        //Update the database
        if(this.userId != -1)
            Main.db.execute("UPDATE `users` SET `user_online`='0', `user_lkey`=NULL WHERE `user_id`=?", ""+this.userId);
        if(this.personaId != -1)
            Main.db.execute("UPDATE `personas` SET `persona_online`='0', `persona_lkey`=NULL WHERE `persona_id`=?", ""+this.personaId);
        
        //Show the disconnect message
        println("Client disconnected!");

        //Remove the client from the list
        SocketServer.removeClient(this);
    }
}
