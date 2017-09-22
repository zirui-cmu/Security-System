/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author zirui
 */
public class PasswordHash {
 
    public String computeHash(String passward){
        byte[] bytesOfMessage = passward.getBytes();
        try{
            //according to specific way of calculating the hash value, return different byte arrays.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] result = md.digest(bytesOfMessage);
            return DatatypeConverter.printHexBinary(result); 
        }catch(NoSuchAlgorithmException e){
            System.out.println("NoSuchAlgorithmException");
        }
        return null;
    }
    
//    public static void main(String[] args){
//        PasswordHash passwordHash = new PasswordHash();
//        System.out.println(passwordHash.computeHash("1moeh"));
//        System.out.println(passwordHash.computeHash("2larryh"));
//        System.out.println(passwordHash.computeHash("3shemph"));
//        
//    }
}
