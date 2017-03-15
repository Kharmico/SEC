/**
 * 
 */
package Test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Hashtable;

import javax.crypto.KeyGenerator;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import org.junit.Test;

import Client.ClientConnections;
import Server.*;

/**
 * @author paulo
 *
 */
public class MainClientTest {

	private static WebTarget target;
	private static Client client;
	private static final String URL = "http://localhost:9000";
	private static final String DOMAIN1 = "google.com";
	private static final String DOMAIN2 = "facebook.com";
	private static final String USER1 = "coolguy";
	private static final String USER2 = "coolguysuper";
	private static final String PASS1 = "12345";
	private static final String PASS2 = "qwerty";
	private static final Key key1=genKey();

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CertificateException 
	 * @throws KeyStoreException 
	 */
	@Test
	public void main() throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {
		
		String [] a = new String[0];
		Server.main(a);
		ClientConnections c = new ClientConnections();
		String k = serialize(key1);
		c.register(k);
		c.put(k,DOMAIN1,USER1,PASS1);
		String pass =c.get(k, DOMAIN1, USER1);
		System.out.println("Passwords PUT "+PASS1+" PasswordGEt "+pass);
		assertEquals(pass,PASS1);
		
	}
	private static Key genKey() {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}
		keyGen.init(128); // for example
		return keyGen.generateKey();
	}
	
	private static String serialize( Serializable o ) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream( baos );
        oos.writeObject( o );
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray()); 
    }

}
