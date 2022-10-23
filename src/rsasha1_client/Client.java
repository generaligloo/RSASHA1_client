/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package RSASHA1_Client;

import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*; 
import java.net.*;
import java.util.Arrays;
/**
 *
 * @author gdocq
 */
class Keyz 
{
    PublicKey pk;
    PrivateKey pr;
        
    void generateRSAKey() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");//creating a pseudo random number generator
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");//creating a key pair generator instance
        kpg.initialize(1024,random);//initializing the key pair generator with key size and a pseudo random number generator
        KeyPair kp = kpg.genKeyPair(); ////generates a key pair
        pk = kp.getPublic(); //get the public key
        pr = kp.getPrivate(); //get the private key
    }
}

public class Client 
{
    public static byte[] rsaEncrypt(byte[] original, PublicKey key) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.ENCRYPT_MODE, key); 
	return cipher.doFinal(original);
    }
    public static byte[] rsaDecrypt(byte[] encrypted, PrivateKey key) throws Exception
    {
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.DECRYPT_MODE, key);
	return cipher.doFinal(encrypted);
    }
    
    public static byte[] getSHA1(byte[] original) 
    {
        byte[] h = null;
        try 
        {    
        System.out.println("Instanciation du digest");
        MessageDigest d = MessageDigest.getInstance("SHA-1");
        System.out.println("Hachage du message");
        d.update(original);
        System.out.println("Generation des bytes");
        h = d.digest();
        System.out.println("Termine : digest construit");
        System.out.println("digest = " + new String(h));
        System.out.println("Longueur du digest = " + h.length);
        }
        catch(Exception ex)
        {
            System.exit(1);
        }
        return h;
    }
    
    public static void main(String args[])
    {
        Keyz CleeClient = new Keyz();
        PublicKey ServerPublickey = null;
        Socket CliSocketSer = null;
        DataOutputStream dos = null;
        try {
            CleeClient.generateRSAKey();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        try
        {
            CliSocketSer = new Socket("localhost", 50000);
            System.out.println(CliSocketSer.getInetAddress().toString());
            dos = new DataOutputStream(CliSocketSer.getOutputStream());
        }
        catch (UnknownHostException e)
        {
            System.err.println("Erreur ! Host non trouvé [" + e + "]");
        }
        catch (IOException e)
        {
            System.err.println("Erreur ! Pas de connexion ? [" + e + "]");
        }
        if (CliSocketSer==null || dos==null) System.exit(1); 
        
        //debut com
        
        try
        {
            InputStream IS = CliSocketSer.getInputStream();
            OutputStream OS = CliSocketSer.getOutputStream();
            ObjectInputStream OBIS = new ObjectInputStream(IS);
            ObjectOutputStream OBOS = new ObjectOutputStream(OS);
            DataInputStream dis = new DataInputStream(IS);
            ServerPublickey = (PublicKey)OBIS.readObject();
            System.out.println("Clé publique du serveur recu:\n" + ServerPublickey);
            
            System.out.println("Envoie clé publique au serveur ...");
            OBOS.writeObject(CleeClient.pk);
            
            String msg = "allo c'est le client !";
            System.out.println("Texte à cacher: \n" + msg);
            
            byte[] msgClair = msg.toString().getBytes();
            byte[] msgCrypt = rsaEncrypt(msgClair, ServerPublickey);
            String texteCryptéAff = new String (msgCrypt);
            System.out.println(new String(msgClair) + " ---> " + texteCryptéAff); 
            byte[] msgdigest = getSHA1(msgClair);
            
            dos.writeInt(msgCrypt.length);
            dos.write(msgCrypt);
            dos.writeInt(msgdigest.length);
            dos.write(msgdigest);
            System.out.println("Message envoyé !"); 
            
            String réponse = dis.readUTF();
            System.out.println("Reponse du serveur = " + réponse);
            
            dos.flush();
            dos.close(); CliSocketSer.close(); OBIS.close(); OBOS.close(); OS.close(); IS.close(); dis.close();
            System.out.println("Client déconnecté");
        } 
        catch (UnknownHostException e)
        { System.err.println("Erreur ! Host non trouvé [" + e + "]"); }
        catch (IOException e)
        { System.err.println("Erreur ! Pas de connexion ? [" + e + "]"); }
        catch (Exception e)
        { System.out.println("Aie aie imprévu " + e.getMessage() + e.getClass()); }
    }
}
