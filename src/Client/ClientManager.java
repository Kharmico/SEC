package Client;

import java.rmi.RemoteException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

//Class com cryptografica
public class ClientManager implements PasswordManager {

	@Override
	public void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void register_user() throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws RemoteException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws RemoteException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}

}
