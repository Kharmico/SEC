/**
 * 
 */
package Server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * @author paulo
 *
 */
public class ServerImpl  implements Server{
	
	
	private KeyStore ks;
	private static final int PORT = 4444;
	
	public ServerImpl(char[] ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		// TODO Auto-generated method stub
		initServer(ksPassword,null);
	}
	
	public ServerImpl(String file,char[] ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		initServer(ksPassword,file);
		
	}
	
	public void safeStore(char[] ksPassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		 // store away the keystore
	    java.io.FileOutputStream fos = null;
	    try {
	        fos = new java.io.FileOutputStream("newKeyStoreName");
	        ks.store(fos, ksPassword);
	    } finally {
	        if (fos != null) {
	            fos.close();
	        }
	    }
	 
	}
	
	private void initServer(char[] password,String file) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
		//
		 java.io.FileInputStream fis = null;
		    try {
		        fis = new java.io.FileInputStream(file);
		        ks.load(fis, password);
		    } finally {
		        if (fis != null) {
		            fis.close();
		        }
		    }
	}
	

	@Override
	public void register(Key publicKey) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) {
		// TODO Auto-generated method stub
		return null;
	}

}
