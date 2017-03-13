/**
 * 
 */
package RemoteTypes;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.*;

import Exceptions.DomainNotFoundException;
import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;

/**
 * @author paulo
 *
 */
public interface IServer  extends Remote {
	
	/**
	 * registers the user in the server. 
	 * @param publicKey
	 * @throws Anomalous or unauthorized an appropriate exception or error code
	 * TODO: error codes??
	 */
	public void register(Key publicKey) throws RemoteException;
	
	/**
	 * stores the triple (domain, username, password) on the server.
	 * This corresponds to an insertion if the (domain, username) pair is not already
	 * known by the server, or to an update otherwise
	 * @param publicKey
	 * @param domain
	 * @param username
	 * @param password
	 */
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password)throws RemoteException;
	
	/**
	 * retrieves the password associated with the given (domain,username) pair.
	 /**
	 * @param publicKey
	 * @param domain
	 * @param username
	 * @return password
	 * @throws UsernameNotFoundException
	 * @throws UsernameNotFoundException
	 */
	
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException;

}
