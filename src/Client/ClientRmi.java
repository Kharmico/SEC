package Client;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.KeyStore.PasswordProtection;
import java.util.Base64;

import RemoteTypes.IServer;

public class ClientRmi implements PasswordManager {
	public static final String DEFAULT_HOST = "localhost";
	public static final String SERVER_NAME = "server";
	private String host;
	private IServer server;
	private KeyPair pair;
	private PasswordProtection ksPassword;

	public ClientRmi(String host) throws RemoteException, NotBoundException {
		this.host = host;
		this.connectServer();

	}

	private void connectServer() throws RemoteException, NotBoundException {
		Registry registry = LocateRegistry.getRegistry(host);
		server = (IServer) registry.lookup(SERVER_NAME);
	}

	@Override
	public void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		pair = keyGen.generateKeyPair();
		this.ksPassword = new PasswordProtection(ksPassword);
	}

	@Override
	public void register_user() throws RemoteException {
		this.server.register(this.pair.getPublic());

	}

	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException {
		this.server.put(this.pair.getPublic(), domain, username, password);

	}

	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException {
		return this.server.get(this.pair.getPublic(), domain, username);
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

}
