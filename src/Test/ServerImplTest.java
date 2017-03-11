/**
 * 
 */
package Test;

import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import javax.crypto.KeyGenerator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import Exceptions.DomainNotFoundException;
import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;
import Server.ByteArrayWrapper;
import Server.ServerImpl;

/**
 * @author paulo
 *
 */
public class ServerImplTest {

	private static final char[] KS_PASS = "a26tUfrGg4e4LHX".toCharArray();
	private static final String KS_PAHT = System.getProperty("user.dir") + "\\Resources\\KeyStore.jks";
	private static final byte[] DOMAIN1 = "google.com".getBytes();
	private static final byte[] DOMAIN2 = "facebook.com".getBytes();
	private static final byte[] USER1 = "coolguy".getBytes();
	private static final byte[] USER2 = "coolguysuper".getBytes();
	private static final byte[] PASS1 = "12345".getBytes();
	private static final byte[] PASS2 = "qwerty".getBytes();
	private Key k1;
	private Key k2;
	private Key k3;

	private ServerImpl s;

	@Before
	public void setUp() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		s = new ServerImpl(KS_PASS);
		k1 = genKey();
		k2 = genKey();
		k3 = genKey();
		assertNotEquals(k1, k2);
		assertNotEquals(k1, k3);
		assertNotEquals(k2, k3);

	}

	/**
	 * Tears down the test fixture. (Called after every test case method.)
	 */
	@After
	public void tearDown() {
		s = null;
		k1 = null;
		k2 = null;
		k3 = null;

	}

	private Key genKey() {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		keyGen.init(256); // for example
		return keyGen.generateKey();
	}

	/**
	 * Test method for {@link Server.ServerImpl#ServerImpl(char[])}.
	 */
	@Test
	public final void testServerImplCharArray() {
		ServerImpl s = null;
		KeyStore ks = null;
		try {
			// pass null a unica coisa que eu acho que deve acontecer é nao
			// permitir o acesso ao ks mas permite o load
			s = new ServerImpl(null);
			ks = s.getKs();
			assertNotNull(ks);

			try {
				s = new ServerImpl("wrongpass".toCharArray());
				ks = s.getKs();
				assertNotNull(ks);
			} catch (Exception e) {
				assert (e instanceof IOException);
			}

			s = new ServerImpl(KS_PASS);
			ks = s.getKs();
			assertNotNull(ks);

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			
			e.printStackTrace();
		}

	}

	/**
	 * Test method for
	 * {@link Server.ServerImpl#ServerImpl(java.lang.String, char[])}.
	 * 
	 */
	@Test
	public final void testServerImplStringCharArray() {

		ServerImpl s = null;
		KeyStore ks = null;

		try {
			try {
				s = new ServerImpl("fakefile.jks", KS_PASS);
				ks = s.getKs();
				assertNull(ks);
			} catch (Exception e) {
				assert (e instanceof FileNotFoundException);
			}
			s = new ServerImpl(KS_PAHT, KS_PASS);

			ks = s.getKs();
			assertNotNull(ks);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			
			e.printStackTrace();
		}

		// TODO
	}

	@Test
	public final void testRegister() {
		try {
			s.register(null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		assertEquals(s.usersSize(), 0);
		s.register(k1);
		s.register(k2);

		assertEquals(s.usersSize(), 2);
		boolean aux = false;
		assert (!aux);
		try {
			s.register(k1);
			assertEquals(s.usersSize(), 2);
		} catch (Exception e) {
			assert (e instanceof UserAlreadyRegisteredException);
			aux = true;
		} finally {
			assert (aux);
		}
		s.register(k3);
		assertEquals(s.usersSize(), 3);

		ByteArrayWrapper pk1 = new ByteArrayWrapper(Base64.getEncoder().encode(k1.getEncoded()));
		ByteArrayWrapper pk2 = new ByteArrayWrapper(Base64.getEncoder().encode(k1.getEncoded()));
		ByteArrayWrapper pk3 = new ByteArrayWrapper(Base64.getEncoder().encode(k3.getEncoded()));
		assertEquals(pk1, pk2);
		assertNotEquals(pk1, pk3);

	}

	/**
	 * Test method for
	 * {@link Server.ServerImpl#put(java.security.Key, byte[], byte[], byte[])}.
	 */
	@Test
	public final void testPut() {
		boolean ex = false;
		try {
			ex = true;
			s.put(null, null, null, null);
		} catch (NullPointerException e) {
			assert (ex);
			ex = false;
		}

		try {
			ex = true;
			s.put(k1, DOMAIN1, USER1, PASS1);
		} catch (UserNotRegisteredException e) {
			assert (ex);
			ex = false;
		}

		s.register(k1);
		s.put(k1, DOMAIN1, USER1, PASS1);
		assertEquals(s.get(k1, DOMAIN1, USER1), PASS1);
		s.put(k1, DOMAIN1, USER1, PASS2);
		assertEquals(s.get(k1, DOMAIN1, USER1), PASS2);
		assertNotEquals(PASS1, PASS2);

		try {
			ex = true;
			s.put(k1, null, null, null);
		} catch (NullPointerException e) {
			assert (ex);
			ex = false;
		}

		try {
			ex = true;
			s.put(k1, DOMAIN1, null, null);
		} catch (NullPointerException e) {
			assert (ex);
			ex = false;
		}

		try {
			ex = true;
			s.put(k1, DOMAIN1, USER1, null);
		} catch (NullPointerException e) {
			assert (ex);
			ex = false;
		}

		assertEquals(s.get(k1, DOMAIN1, USER1), PASS2);
		s.put(k1, DOMAIN1, USER1, PASS1);
		assertEquals(s.get(k1, DOMAIN1, USER1), PASS1);
		assertNotEquals(PASS1, PASS2);

		s.put(k1, DOMAIN1, USER1, PASS1);
		s.put(k1, DOMAIN1, USER2, PASS2);
		assertEquals(s.get(k1, DOMAIN1, USER1), PASS1);
		assertEquals(s.get(k1, DOMAIN1, USER2), PASS2);

		s.register(k2);
		s.put(k1, DOMAIN2, USER1, PASS1);
		s.put(k2, DOMAIN2, USER1, PASS2);
		assertEquals(s.get(k1, DOMAIN2, USER1), PASS1);
		assertEquals(s.get(k2, DOMAIN2, USER1), PASS2);
		s.put(k1, DOMAIN2, USER1, PASS1);
		s.put(k1, DOMAIN2, USER2, PASS2);
		assertEquals(s.get(k1, DOMAIN2, USER1), PASS1);
		assertEquals(s.get(k1, DOMAIN2, USER2), PASS2);

	}

	/**
	 * Test method for
	 * {@link Server.ServerImpl#get(java.security.Key, byte[], byte[])}.
	 */
	@Test
	public final void testGet() {
		boolean aux = false;

		try {
			aux = true;
			s.get(null, null, null);
		} catch (NullPointerException e) {
			assert (aux);
			aux = false;
		}
		s.register(k1);
		s.register(k2);
		try {
			aux = true;
			s.get(null, null, null);
		} catch (NullPointerException e) {
			assert (aux);
			aux = false;
		}
		try {
			aux = true;
			s.get(k1, null, null);
		} catch (NullPointerException e) {
			assert (aux);
			aux = false;
		}
		try {
			aux = true;
			s.get(k1, DOMAIN1, null);
		} catch (NullPointerException e) {
			assert (aux);
			aux = false;
		}
		try {
			aux = true;
			s.get(k1, DOMAIN1, USER1);
		} catch (DomainNotFoundException e) {
			assert (aux);
			aux = false;
		}

		s.put(k1, DOMAIN1, USER1, PASS1);
		try {
			aux = true;
			s.get(k1, DOMAIN1, USER2);
		} catch (UsernameNotFoundException e) {
			assert (aux);
			aux = false;
		}

		try {
			aux = true;
			s.get(k3, DOMAIN1, USER1);
		} catch (UserNotRegisteredException e) {
			assert (aux);
			aux = false;
		}
		s.put(k1, DOMAIN1, USER1, PASS1);
		
		assertEquals(s.get(k1, DOMAIN1, USER1),PASS1);
		

	}

//	/**
//	 * Test method for {@link Server.ServerImpl#safeStore(char[])}.
//	 */
//	@Test
//	public final void testSafeStore() {
//		fail("Not yet implemented"); //TODO
//	}

	
}
