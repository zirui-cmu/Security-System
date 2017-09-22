import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Random;

public class TCPInstallerUsingTEAandPasswordsAndRSA {
	public static void main(String[] args) throws Exception{
        Socket clientSocket = null;
        try {
            int serverPort = 7896;
            clientSocket = new Socket("localhost", serverPort); 
            // random generate 16 byte keys. 
            BigInteger e = new BigInteger ("65537");
            BigInteger n = new BigInteger("5602703955623631334465493895058218485977434383448498280117017687835425785334336047219423818671123709007146167300706546390992278607656692861742305018214607161442279294613183952894036666875717252788752920159526871964234106560517480239405838699");
            Random rnd = new Random();
            BigInteger bigkey = new BigInteger(16*8,rnd);
            String key = bigkey.toString().substring(0,16);
            BigInteger bigIntegerKey = new BigInteger(key);
            //System.out.println("key:"+key);
            //To encrypt a message M compute C = M^e (mod n) and send it to server
            BigInteger c = bigIntegerKey.modPow(e, n);
            //System.out.println("c:"+c);
            DataOutputStream out =new DataOutputStream(clientSocket.getOutputStream());
            out.write(c.toByteArray());
            out.flush();
            
            //get user input information
            BufferedReader typed = new BufferedReader(new InputStreamReader(System.in));     
            byte[] keyByte = key.getBytes();
            TEA tea = new TEA(keyByte);
            
            System.out.println("Enter your ID:");
            String userId = typed.readLine();
            
            System.out.println("Enter your Password:");
            String password = typed.readLine();
            
            System.out.println("Enter sensor ID:");
            String sensorId = typed.readLine();
            
            System.out.println("Enter new sensor location:");
            String location = typed.readLine();
            //encryption
            String information = toJSON(userId, password, sensorId, location);
            byte[] encryptedJSON = tea.encrypt(information.getBytes());
            //System.out.println(encryptedJSON);
            //send encrypted JSON to server
            
            out.write(encryptedJSON); 
            out.flush();
            //get return from server
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            int length = clientSocket.getInputStream().available();
            
            while(length == 0){
            	length = clientSocket.getInputStream().available();
            	Thread.sleep(1000);
            	
            }
            byte[] messagefromserver = new byte[length];
            in.read(messagefromserver);
            byte[] decryptedMsg = tea.decrypt(messagefromserver);
            String returnMessage = new String(decryptedMsg);
            //System.out.println(returnMessage);
            for (int i = 0; i < returnMessage.length(); i++){
                if(returnMessage.charAt(i)>128){
                    throw new Exception("Illegal symmetric key");    
                }
            }
       
            System.out.println(returnMessage);
            
            out.close();
            in.close();
            
        } catch (EOFException e){
            System.out.println("EOF:"+e.getMessage());   
	    }catch (IOException e){
            System.out.println("readline:"+e.getMessage());
        } catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}finally {
            if(clientSocket!=null) 
                try {clientSocket.close();}
                catch (IOException e){
                    System.out.println("close:"+e.getMessage());
                }
        }
    }
    
    /*
    *This is a function to convert a string to json format.
    */
    public static String toJSON(String userId, String password, String sensorId, String location){
        StringBuffer json = new StringBuffer();
        json.append("{\"ID\":\""+userId+"\",");
        json.append("\"passwd\":\""+password+"\",");
        json.append("\"Sensor ID\":"+sensorId+",");
        json.append("\"Longitude\":"+location.split(",")[0]+",");
        json.append("\"Latitude\":"+location.split(",")[1]+"}");
        //System.out.println("Here is the JSON of message sent to server\n"+json.toString());
        return json.toString();
    }
}
