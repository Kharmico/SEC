/**
 * 
 */
package Test;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;

import org.junit.Before;
import org.junit.Test;

import Client.ClientConnections;
//
import Exceptions.DomainNotFoundException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;
import Server.*;

/**
 * @author paulo
 *
 */
public class ClientServerTest {

	private static WebTarget target;
	private static Client client;
	private static final String URL = "http://localhost:9000";
	private static final String DOMAIN1 = "google.com";
	private static final String DOMAIN2 = "facebook.com";
	private static final String USER1 = "coolguy";
	private static final String USER2 = "coolguysuper";
	private static final String PASS1 = "12345";
	private static final String PASS2 = "qwerty";
	private static final Key key1 = genKey();
	private static final Key key2 = genKey();
	private static final Key key3 = genKey();
	ClientConnections c;
	String k1;
	String k2;
	String k3;

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 */

	@Test
	public void testRegisterRemote()
			throws NoSuchAlgorithmException, IOException, KeyStoreException, CertificateException {
		String[] a = new String[0];
		Server.main(a);
		
		c = new ClientConnections();
		
		k1 = serialize(key1);
		k2 = serialize(key2);
		k3 =serialize(key3);
		c.register(k1);
		boolean ex = false;
		try {

			c.get(null, null, null);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		c.put(k1, DOMAIN1, USER1, PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS1);
		c.put(k1, DOMAIN1, USER1, PASS2);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS2);
		c.put(k1, DOMAIN1, USER2, PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER2), PASS1);

		c.register(k2);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS2);
		c.put(k2, DOMAIN1, USER1, PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS2);
		assertEquals(c.get(k2, DOMAIN1, USER1), PASS1);

		boolean exp = false;
		try {

			c.register(k1);
		} catch (BadRequestException e) {
			exp = true;
		}
		assert (exp);
		exp = false;

		try {

			c.register(null);
		} catch (BadRequestException e) {
			exp = true;
		}
		assert (exp);
		exp = false;
		testPutRemote();
		testGet();
	}


	public void testPutRemote() throws UnsupportedEncodingException {
		boolean ex = false;
		try {

			c.put(null, null, null, null);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		try {

			c.put(k3, DOMAIN1, USER1, PASS1);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		
		c.put(k1, DOMAIN1, USER1, PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS1);
		c.put(k1, DOMAIN1, USER1, PASS2);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS2);
		assertNotEquals(PASS1, PASS2);

		try {

			c.put(k1, null, null, null);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		try {

			c.put(k1, DOMAIN1, null, null);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		try {

			c.put(k1, DOMAIN1, USER1, null);
		} catch (BadRequestException e) {
			ex = true;
		}
		assert (ex);
		ex = false;
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS2);
		c.put(k1, DOMAIN1, USER1, PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS1);
		assertNotEquals(PASS1, PASS2);

		c.put(k1, DOMAIN1, USER1, PASS1);
		c.put(k1, DOMAIN1, USER2, PASS2);
		assertEquals(c.get(k1, DOMAIN1, USER1), PASS1);
		assertEquals(c.get(k1, DOMAIN1, USER2), PASS2);

		c.put(k1, DOMAIN2, USER1, PASS1);
		c.put(k2, DOMAIN2, USER1, PASS2);
		assertEquals(c.get(k1, DOMAIN2, USER1), PASS1);
		assertEquals(c.get(k2, DOMAIN2, USER1), PASS2);
		c.put(k1, DOMAIN2, USER1, PASS1);
		c.put(k1, DOMAIN2, USER2, PASS2);
		assertEquals(c.get(k1, DOMAIN2, USER1), PASS1);
		assertEquals(c.get(k1, DOMAIN2, USER2), PASS2);
	}
	
	private void testGet() throws UnsupportedEncodingException{
		boolean aux = false;

		try {

			c.get(null, null, null);
		} catch (BadRequestException e) {
			aux = true;
		}
		assert (aux);
		aux = false;
		
		try {

			c.get(null, null, null);
		} catch (BadRequestException e) {
			aux = true;
		}
		assert (aux);
		aux = false;
		try {

			c.get(k1, null, null);
		} catch (BadRequestException e) {
			aux = true;
		}
		assert (aux);
		aux = false;

		try {

			c.get(k1, DOMAIN1, null);
		} catch (BadRequestException e) {
			aux = true;
		}
		assert (aux);
		aux = false;

		try {

			c.get(k3, DOMAIN1, USER1);
		} catch (BadRequestException e) {
			aux = true;
		}
		assert (aux);
		aux = false;
		c.put(k1, DOMAIN1, USER1, PASS1);

		assertEquals(c.get(k1, DOMAIN1, USER1), PASS1);

	
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

	private static String serialize(Serializable o) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(o);
		oos.close();
		return Base64.getEncoder().encodeToString(baos.toByteArray());
	}

}
