/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 *
 * @author zirui
 */
public class TCPInstallerUsingTEAandPasswords {
    public static void main(String[] args) throws Exception{
        Socket clientSocket = null;
        try {
            int serverPort = 7896;
            clientSocket = new Socket("localhost", serverPort);            
            //get user input information
            BufferedReader typed = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter symmetric key as a 16-digit integer.");
            String key = typed.readLine().substring(0, 16);
            //System.out.println(key);
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
            DataOutputStream out =new DataOutputStream(clientSocket.getOutputStream());
            out.write(encryptedJSON); 
            out.flush();
            //get return from server
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            int length = clientSocket.getInputStream().available();
            //get message length
            while(length == 0){
            	length = clientSocket.getInputStream().available();
            	Thread.sleep(1000);
   
            }
            byte[] messagefromserver = new byte[length];
            in.read(messagefromserver);
            byte[] decryptedMsg = tea.decrypt(messagefromserver);
            String returnMessage = new String(decryptedMsg);
            //System.out.println(returnMessage);
            //if the message returned is not asc2 chracter, it is a bad symmetric key
            for (int i = 0; i < returnMessage.length(); i++){
                if(returnMessage.charAt(i)>128){
                    throw new Exception("Illegal symmetric key");    
                }
            }
       
            System.out.println(returnMessage);
             
            
            out.close();
            in.close();
            
        } catch (EOFException e){
            System.out.println("EOF:"+"Exception");   
	    }catch (IOException e){
            System.out.println("readline:"+"Exception");
        } catch (InterruptedException e) {
		// TODO Auto-generated catch block
		System.out.print("InterrupedException");
	}finally {
            if(clientSocket!=null) 
                try {clientSocket.close();}
                catch (IOException e){
                    System.out.println("close: Exception");
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
