package Client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import Crypto.KeyStoreFunc;
/**
 * @author Joao
 *
 */
public class ClientApp {

	private static final String KS_PATH = System.getProperty("user.dir") + "\\Resources\\KeyStoreBob.jceks";
	
	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	/* Application to communicate with the ClientManager in order to apply the specifications of
	 * execution of the client library for the project.
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		Scanner readIns = new Scanner(System.in);
		ClientManager cman = new ClientManager();
		KeyStoreFunc kstorefunc = new KeyStoreFunc();

		// Variables to use for passing arguments for ClientManager. Must initialize them (give them a value)
		String keystore = new String();
		char[] ksPassword = null;
		byte[] domain = null;
		byte[] username = null;
		byte[] password = null;
		
		System.out.println("To know which instructions are usable, use the \"help\" function");
		while(true){
			String[] tokens = readIns.nextLine().split(" ");
			
			switch (tokens[0].toLowerCase()) {
				case "help":
					System.out.println("The instructions are as follows:\ninit <KeyStore name> <Password>\nregister_user\n"
							+ "save_password<domain> <username> <password>\nretrieve_password <domain> <username>\nclose");
				case "init":
					if(tokens.length == 3) {
						keystore = tokens[1];
						KeyStore ks = null;
						kstorefunc.loadKeyStore(KS_PATH);
						ks = kstorefunc.getKeyStore();
						ksPassword = tokens[2].toCharArray();
						cman.init(ks, ksPassword);
					}
					else System.out.println("You did not insert at least 1 argument for this instruction.\n"
							+ "The correct usage is init <KeyStore name> <Password>");
					
				case "register_user":
					if(tokens.length == 1)
						cman.register_user();
					else System.out.println("Wrong usage of the instruction.\n"
							+ "The correct usage is register_user");
					
				case "save_password":
					if(tokens.length == 4) {
						domain = tokens[1].getBytes();
						username = tokens[2].getBytes();
						password = tokens[3].getBytes();
						cman.save_password(domain, username, password);
					}
					else System.out.println("You did not insert at least 1 argument for this instruction.\n"
							+ "The correct usage is save_password <domain> <username> <password>");
					
				case "retrieve_password":
					if(tokens.length == 3){
						domain = tokens[1].getBytes();
						username = tokens[2].getBytes();
						cman.retrieve_password(domain, username);
					}
					else System.out.println("You did not insert at least 1 argument for this instruction.\n"
							+ "The correct usage is retrieve_password <domain> <username>");
					
				case "close":
					if(tokens.length == 1)
						cman.close();
					else System.out.println("Wrong usage of the instruction.\n"
							+ "The correct usage is close");
					
				default:
					System.out.println("The instruction you've typed does not exist! Please try again.");
			}		
		}
	}
}
