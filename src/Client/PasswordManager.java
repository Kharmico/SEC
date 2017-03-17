/**
 * 
 */
package Client;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.DestroyFailedException;

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
	 * @throws IOException 
	 * @throws ClassNotFoundException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableEntryException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeySpecException
	 * @throws InvalidAlgorithmParameterException 
	 */
	void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException, ClassNotFoundException, IOException, InvalidKeyException, UnrecoverableEntryException, KeyStoreException, SignatureException, InvalidKeySpecException, InvalidAlgorithmParameterException;
	
	/**
	 * @throws RemoteException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableEntryException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 * @throws Exception 
	 * 
	 */
	void register_user() throws RemoteException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, IOException, InvalidKeyException, SignatureException, Exception;
	
	/**
	 * 
	 * @param domain
	 * @param username
	 * @param password
	 * @throws Exception 
	 */
	void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, InvalidKeyException, SignatureException, Exception;
	
	/**
	 * 
	 * @param domain
	 * @param username
	 * @return
	 * @throws RemoteException 
	 * @throws Exception 
	 */
	byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException, Exception;
	
	/**
	 * @throws DestroyFailedException 
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * 
	 */
	void close() throws DestroyFailedException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;
}
