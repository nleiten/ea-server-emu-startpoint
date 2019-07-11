package bf2142emulator;

import java.sql.*;

/**
 *
 * @author Freek
 */
public class Database {

    private Connection conn     = null;

    public Database(String address, String username, String password, String database)
    {
        try{
            //Create the database connection
            Class.forName("com.mysql.jdbc.Driver").newInstance();
            conn        =  DriverManager.getConnection("jdbc:mysql://"+address+"/"+database,username,password);
        }
        catch(Exception e) {
            //Could not connect to database
            e.printStackTrace();
            System.out.println("Database error: "+ e.getMessage() +" - "+e.getLocalizedMessage());
            System.exit(-1);
        }
    }

    public ResultSet query(String query) {
         try {
             //Execute the query
             Statement stat     = conn.createStatement();
             return stat.executeQuery(query);
        }
        catch(Exception e) {
            System.out.println("Database warning: "+e.getMessage());
            return null;
        }
     }

     public ResultSet query(String query, String... argList) {
         try {
             //Execute the query
             PreparedStatement prepStat     = conn.prepareStatement(query);

             int counter = 1;
             for(String arg : argList) {
                 prepStat.setString(counter, arg);
                 counter++;
             }
             
             return prepStat.executeQuery();
        }
        catch(Exception e) {
            System.out.println("Database warning: "+e.getMessage());
            return null;
        }
     }

     public boolean execute(String query) {
         try {
             //Execute the query
             Statement stat     = conn.createStatement();
             return stat.execute(query);
        }
        catch(Exception e) {
            System.out.println("Database warning: "+e.getMessage());
            return false;
        }
     }

     public boolean execute(String query, String... argList) {
         try {
             //Execute the query
             PreparedStatement prepStat     = conn.prepareStatement(query);

             int counter = 1;
             for(String arg : argList) {
                 prepStat.setString(counter, arg);
                 counter++;
             }

             return prepStat.execute();
        }
        catch(Exception e) {
            System.out.println("Database warning: "+e.getMessage());
            return false;
        }
     }

}
