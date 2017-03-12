package Client;

import java.net.*;
import java.io.*;
import java.security.*;

 
public class Client{
  private String serverName = "localhost";
  private static int PORT = 4444;
 
  private PublicKey publicKey = null;
  private PrivateKey privateKey = null;
  private String username = null;
  
  //Initiate connection with the server, given the username and PubKey
  public int FS_init(){
	  try{
		  System.out.println("Connecting to " + serverName + " on port " + PORT);
		  Socket client = new Socket(serverName, PORT);
		  System.out.println("Just connected to " + client.getRemoteSocketAddress());

		  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		  SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		  keyGen.initialize(1024, random);
		  KeyPair pair = keyGen.generateKeyPair();
		  privateKey = pair.getPrivate();
		  publicKey = pair.getPublic(); 
		  byte[] pubKey = publicKey.getEncoded();
		  BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		  String username = br.readLine();
 
		  OutputStream outToServer = client.getOutputStream();
		  DataOutputStream out = new DataOutputStream(outToServer);
		  out.writeUTF("1:---" + username + ";" + "-----" + pubKey.length);
		  out.write(pubKey);
		  InputStream inFromServer = client.getInputStream();
		  DataInputStream in = new DataInputStream(inFromServer);
		  int idToUse = Integer.parseInt(in.readUTF());
 
		  client.close();
 
		  return idToUse;
      }
      catch(NoSuchAlgorithmException e){
         e.printStackTrace();
      }
      catch(IOException e){
         e.printStackTrace();
      }
      return 0;
  }
  
  //just testing, lot of stuff missing
  public static void main(String [] args) {
	  Client user = new Client();
	  user.FS_init();
	  
	  System.out.println("Welcome to the filesystem: " + user.username);  
  }
}