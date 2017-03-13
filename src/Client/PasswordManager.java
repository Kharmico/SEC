/**
 * 
 */
package Client;

import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

/**
 * @author paulo
 *
 */
public interface PasswordManager {
	
	/**
	 * 
	 * @param ks
	 * @param ksPassword
	 * @throws NoSuchAlgorithmException 
	 */
	void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException;
	
	/**
	 * @throws RemoteException 
	 * 
	 */
	void register_user() throws RemoteException;
	
	/**
	 * 
	 * @param domain
	 * @param username
	 * @param password
	 * @throws RemoteException 
	 */
	void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException;
	
	/**
	 * 
	 * @param domain
	 * @param username
	 * @return
	 * @throws RemoteException 
	 */
	byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException;
	
	/**
	 * 
	 */
	void close();
}
