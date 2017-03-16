package Client;

import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

//Class com cryptografica
public class ClientManager implements PasswordManager {

	private String stuff = "";
	private KeyStore _ks = null;
	char[] _ksPassword = null;
	ClientConnections clientconn = null;
	
	
	@Override
	public void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException {
		this._ks = ks;
		this._ksPassword = ksPassword;
		clientconn = new ClientConnections();
		
		
		/*Specification: initializes the library before its first use. This method should
		receive a reference to a key store that must contain the private and public key
		of the user, as well as any other parameters needed to access this key store
		(e.g., its password) and to correctly initialize the cryptographic primitives used
		at the client side. These keys maintained by the key store will be the ones used
		in the following session of commands issued at the client side, until a close()
		function is called.*/
	}

	@Override
	public void register_user() throws RemoteException {
		
		
		// Get the public key to send!!!
		clientconn.register(pubKey);
		
		/*Specification: registers the user on the server, initializing the required data
		structures to securely store the passwords.*/
		
	}

	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException {
		
		
		// Get the public key to send!!!
		clientconn.put(pubKey, domain, username, password);
		
		/*Specification: stores the triple (domain, username, password) on the server.
		This corresponds to an insertion if the (domain, username) pair is not already
		known by the server, or to an update otherwise.
		 */
		
	}

	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException {
		
		
		// Get the public key to send!!!
		clientconn.get(pubKey, domain, username);
		
		/*Specification: retrieves the password associated with the given (domain,
		username) pair. The behavior of what should happen if the (domain,
		username) pair does not exist is unspecified.
		 */
		return null;
	}

	@Override
	public void close() {
		
		
		
		
		// concludes the current session of commands with the client library.
		
	}

}
