/**
 * 
 */
package Server;

import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.Key;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import Exceptions.UserAlreadyRegisteredException;
import RemoteTypes.IServer;

/**
 * @author paulo
 *
 */
public class Server implements IServer {

	public static final String SERVER_NAME = "Server";
	private static final PasswordProtection DEFAULT_KS_PASSWORD = new PasswordProtection("a26tUfrGg4e4LHX".toCharArray());
	private static final int PORT= 4444;
	
	private static Manager manager;

	public Server() {
	}

	/**
	 * @param args
	 * @throws IOException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws AlreadyBoundException
	 */
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
			IOException, AlreadyBoundException {
		if (args.length == 0) {
			manager = new Manager(DEFAULT_KS_PASSWORD.getPassword());
		} else {
			manager = args.length > 1 ? new Manager(args[1], args[0].toCharArray())
					: new Manager(args[0].toCharArray());
		}
		Server obj = new Server();
		IServer stub = (IServer) UnicastRemoteObject.exportObject(obj, 0);

		// Bind the remote object's stub in the registry
		Registry registry = LocateRegistry.getRegistry(PORT);
		registry.bind(SERVER_NAME, stub);
		System.err.println("Server ready");

	}

	@Override
	public void register(Key publicKey) throws RemoteException {
		// TODO Auto-generated method stub
		manager.register(publicKey);

	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		manager.put(publicKey, domain, username, password);
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return manager.get(publicKey, domain, username);
	}

}
