/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.JSONException;
import org.json.JSONObject;


/**
 *
 * @author zirui
 */
public class TCPGunShotIncUsingTEAandPasswords {
    public static void main(String[] args){
        try {
            int serverPort = 7896;
            ServerSocket listenSocket = new ServerSocket(serverPort);
            BufferedReader typed = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter symmetric key as a 16-digit integer.");
            String key = typed.readLine().substring(0, 16);
            //System.out.println(key);
            System.out.println("Waiting for installers to visit...");
            while (true) {
                Socket clientSocket = listenSocket.accept();
                MultithreadServer server = new MultithreadServer(clientSocket, key);
            }
        } catch (IOException e) {
            System.out.println("Listen socket:" + e.getMessage());
        }
    }   
}

class MultithreadServer extends Thread{
        static int count;
        Socket clientSocket;
        DataInputStream in;
        DataOutputStream out;
        String key;
        int messageLen;
        String kmlfile; //the content of kml file
        String position; //position of the sensor
        String id; //sensor id
        
        static Map<String, List<Integer>> sensorIds = new HashMap<String, List<Integer>>();
        static Map<String, String> sensorPosition = new HashMap<String, String>();
        
        //when get a clientSocket, initialize the DataInputStream and the DataOutputStream and key
        //In the meantime, start the thread.
        public MultithreadServer(Socket clientSocket, String key){
            try {
                this.clientSocket = clientSocket;
                this.key = key;
                messageLen = clientSocket.getInputStream().available();
                while(messageLen == 0){
                	messageLen = clientSocket.getInputStream().available(); //get the meassage's length
                	Thread.sleep(1000);
                	//System.out.println(messageLen);
                }
                
                //System.out.println(messageLen);
                in = new DataInputStream(clientSocket.getInputStream());
                out = new DataOutputStream(clientSocket.getOutputStream());
                this.start();
            } catch (IOException | InterruptedException e) {
                System.out.println("Connection:" + e.getMessage());
            }
        }
        @Override
        public void run(){
            Map<String, String> salt = new HashMap<String, String>(); //the key is the id and value is the salt
            salt.put("Moe", "1");
            salt.put("Larry", "2");
            salt.put("Shemp", "3");
            
            Map<String, String> saltedpw = new HashMap<String, String>();
            saltedpw.put("Moe", "1F2DF417EC36E5B6CA0275F2F24979C751574ECAAE68F3433A9C428E8CD7D767"); // the key is thd id and the value is the hashcode
            saltedpw.put("Larry", "15C5FDA214FFF6BC98E9D44A2F63817F750DEFFA57B919EAC22697B29DF447BF");
            saltedpw.put("Shemp", "DCDCD66BAB347E5A56E5A8C3BD2EE0F50E412721C9A8E30A2620ABCEA174042B");      
            
            count++;
            byte[] messagefromclient = new byte[messageLen];
            try {
                in.read(messagefromclient);
            } catch (IOException ex) {
                Logger.getLogger(MultithreadServer.class.getName()).log(Level.SEVERE, null, ex);
            }
            //decrypt the message
            TEA tea = new TEA(key.getBytes());
            String decryptedJSON = new String(tea.decrypt(messagefromclient));
            //System.out.println(decryptedJSON);
            //detecting the use of a bad symmetric key 
            String returnMessage = "";
            for(int i = 0; i < decryptedJSON.length(); i++){
                if(decryptedJSON.charAt(i)>128){
                    returnMessage = "illegal symmetric key";
                    try {
                        out.write(tea.encrypt(returnMessage.getBytes()));
                        out.flush();
                    } catch (IOException ex) {
                        Logger.getLogger(MultithreadServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                    System.out.printf("Got visit %d illegal symmetric key used. This may be an attack.%n", count);
                    return;
                }
            }
            try {
                //paser the json string
                JSONObject jsonObject = new JSONObject(decryptedJSON);
                String userId = jsonObject.getString("ID");
                String paswd = jsonObject.getString("passwd");
                int sensorId = jsonObject.getInt("Sensor ID");
                double latValue = jsonObject.getDouble("Latitude"); 
                double longValue = jsonObject.getDouble("Longitude");
                //identification and authentication 
                
                //if userid is value
                if(salt.containsKey(userId)){
                    PasswordHash passwordHash = new PasswordHash();
                    String hashvalue = passwordHash.computeHash(salt.get(userId)+paswd);
                    if(hashvalue.equals(saltedpw.get(userId))){ //password is valid
                        if(sensorIds.containsKey(userId)&&userId.equals("Moe")){ //only installer "Moe" can update his sensor location
                            if(sensorIds.get(userId).contains(sensorId)){
                                System.out.println("Got visit " + count + " from " + userId + " Chief Sensor Installer, a sensor has been moved.");
                                sensorIds.get(userId).add(sensorId);
                                returnMessage = "Thank you. The sensor's new location was securely transmitted to GunshotSensing Inc.";
                                position = String.valueOf(longValue)+","+String.valueOf(latValue)+",0.00000";
                                id = String.valueOf(sensorId);
                                sensorPosition.put(id, position);
                                createKMLFile(); //update kml file
                            } else { //else moe installed another sensor
                                System.out.println("Got visit " + count + " from " + userId + " Chief Sensor Installer");
                                sensorIds.get(userId).add(sensorId);
                                returnMessage = "Thank you. The sensor's location was securely transmitted to GunshotSensing Inc.";
                                position = String.valueOf(longValue)+","+String.valueOf(latValue)+",0.00000";
                                id = String.valueOf(sensorId);
                                sensorPosition.put(id,position);
                                createKMLFile(); //update kml file
                            }
                            
                      	  	
                        }else{
                        	if(sensorIds.containsKey(userId)){
                                    if(sensorIds.get(userId).contains(sensorId)) { //others cannot change sensor location
                                        returnMessage = "Not authorized to change the sensor location";
                                        System.out.println("Got visit " + count + " from " + userId + ", Not authorized to change the sensor location");
                                    } else { //else others installed another sensors
                                        returnMessage = "Thank you. The sensor's location was securely transmitted to GunshotSensing Inc.";
                                        System.out.println("Got visit " + count + " from " + userId + ", Associate Sensor Installer");
                                        position = String.valueOf(longValue)+","+String.valueOf(latValue)+",0.00000";
                                        id = String.valueOf(sensorId);
                                        sensorPosition.put(id,position);
                                        createKMLFile();
                                    }
                        	    
                        	}else{
                        	//first create installer
                                sensorIds.put(userId, new ArrayList<Integer>()); 
                                sensorIds.get(userId).add(sensorId);
                                if(userId.equals("Moe")){
                                	System.out.println("Got visit " + count + " from " + userId + ", Chief Sensor Installer");
                                	position = String.valueOf(longValue)+","+String.valueOf(latValue)+"0.00000";
                                	id = String.valueOf(sensorId);
                                        sensorPosition.put(id,position);
                                }else{
                                	System.out.println("Got visit " + count + " from " + userId + ", Associate Sensor Installer");
                                	if(userId.equals("Larry")){
                                		position = String.valueOf(longValue)+","+String.valueOf(latValue)+"0.00000";
                                		id = String.valueOf(sensorId);
                                                sensorPosition.put(id, position);
                                	}else{
                                		position = String.valueOf(longValue)+","+String.valueOf(latValue)+"0.00000";
                                		id = String.valueOf(sensorId);
                                                sensorPosition.put(id,position);
                                	}
                                }
                                returnMessage = "Thank you. The sensor's location was securely transmitted to GunshotSensing Inc.";
                                createKMLFile(); //update kml file
                        	} 	
                        }
                    }else{ //passward is not valid
                        returnMessage = "Illegal ID or Password";
                        if(userId.equals("Moe")){
                            System.out.println("Got visit " + count + " from " + userId + ", Chief Sensor Installer");
                            System.out.println("Illegal Password attempt. This may be an attack.");
                        }else{
                            System.out.println("Got visit " + count + " from " + userId + ", Associate Sensor Installer");
                            System.out.println("Illegal Password attempt. This may be an attack.");
                        }
                    }
                }else{ //userid does not exist
                    returnMessage = "Illegal ID or Password";
                    System.out.printf("Got visit %d from unauthroized user. Illegal Password attempt. This may be an attack.%n", count);
                }
               
                out.write(tea.encrypt(returnMessage.getBytes()));
                out.flush();
     
            } catch (JSONException ex) {
                Logger.getLogger(MultithreadServer.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(MultithreadServer.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {if (clientSocket != null)
                        clientSocket.close();
                }catch (IOException e) {
                    System.out.println("when close the client socket, exception occurs.");
                }
            }
        }
        
        public void createKMLFile(){
            kmlfile = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"+
                    "<kml xmlns=\"http://earth.google.com/kml/2.2\"\n" +
                    "><Document>"+
                    "<Style id=\"style1\">\n" +
                    "<IconStyle>\n" +
                    "<Icon>\n" +
                    "<href>http://icons.iconarchive.com/icons/pelfusion/long-shadowmedia/128/Microphone-icon.png</href>\n" +
                    "</Icon>\n" +
                    "</IconStyle>\n" +
                    "</Style>\n"; 
            for (String sensorid : sensorPosition.keySet()){ //iteratively add sensors' locations
                kmlfile +=  "<Placemark>\n" +
                        "<name>"+sensorid+"</name>\n" +
                        "<description>Larry</description>\n" +
                        "<styleUrl>#style1</styleUrl>\n" +
                        "<Point>\n" +
                        "<coordinates>"+sensorPosition.get(sensorid)+"</coordinates>\n" +
                        "</Point>\n" +
                        "</Placemark>\n";
            }
            kmlfile += "</Document>\n" +
                        "</kml>";
            
            BufferedWriter out = null;
            FileWriter fw = null;
			try {
				fw = new FileWriter("InsatlledSensors.kml",false); //false defines overriding not appendding
				out = new BufferedWriter(fw);
				//System.out.println(kmlfile);
				out.write(kmlfile);
				out.flush();
				
            } catch (IOException e) {
                e.printStackTrace();
			}finally {
				try {
					if (out != null)
						out.close();
					if (fw != null)
						fw.close();

				} catch (IOException ex) {
					ex.printStackTrace();
				}
			}
        }      
    }
