package Test;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.KeyGenerator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import Exceptions.DomainNotFoundException;
import Exceptions.UsernameNotFoundException;
import Server.ByteArrayWrapper;
import Server.User;
import junit.framework.TestCase;

public class UserTest extends TestCase {

	private ByteArrayWrapper pubKey;
	private static final byte[] DOMAIN1 = "google.com".getBytes();
	private static final byte[] DOMAIN2 = "facebook.com".getBytes();
	private static final byte[] USER1 = "coolguy".getBytes();
	private static final byte[] USER2 = "coolguysuper".getBytes();
	private Map<ByteArrayWrapper, Hashtable<ByteArrayWrapper, ByteArrayWrapper>> userTriples;
	private Hashtable<ByteArrayWrapper, ByteArrayWrapper> userNamesDuples;
	byte[] p1 = "superPass".getBytes();
	byte[] p1Copy="superPass".getBytes();
	byte[] p2 = "superPass2".getBytes();
	byte[] p2Copy="superPass2".getBytes();
	byte[] p3 = "novaPass".getBytes();
	byte[] p3Copy="novaPass".getBytes();
	/**
	 * Sets up the test fixture. (Called before every test case method.)
	 */
	@Before
	public void setUp() {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
		
			e.printStackTrace();
		}
		keyGen.init(256); // for example
		pubKey = new ByteArrayWrapper(Base64.getEncoder().encode(keyGen.generateKey().getEncoded()));
		userTriples = new Hashtable<ByteArrayWrapper, Hashtable<ByteArrayWrapper, ByteArrayWrapper>>();
		userNamesDuples= new Hashtable<ByteArrayWrapper, ByteArrayWrapper>();

	}

	/**
	 * Tears down the test fixture. (Called after every test case method.)
	 */
	@After
	public void tearDown() {
		pubKey = null;
		userTriples = null;
		userNamesDuples=null;
	}

	@Test
	public final void testUser() {
		User u = new User(pubKey);
		assertNotNull(u);
		assertEquals(u.getPubKey(), pubKey);

		u = new User(null);
		assertNull(u.getPubKey());

	}

	@Test
	public final void testGetPubKey() {
		User u = new User(pubKey);
		assertEquals(u.getPubKey(), pubKey);

		u = new User(null);
		assertNull(u.getPubKey());
		ByteArrayWrapper aux = (ByteArrayWrapper) pubKey.clone();
		u = new User(aux);
		assertEquals(u.getPubKey(), aux);
		assertEquals(u.getPubKey(), pubKey);
	}

	@Test
	public final void testPut() {
		User u = new User(pubKey);
		//-------------------------------------
		try {
			u.put(null, null, null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		
		try {
			u.put(DOMAIN2, USER1, null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		
		try {
			u.put(DOMAIN2, null, null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		try {
			u.put(null, USER1, "pass".getBytes());
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		//-------------------------------------
		//Test size of domains map in user
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),0);

		

		u.put(DOMAIN1, USER1, p1);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),1);
		
		u.put(DOMAIN1, USER2, p2);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN1, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2Copy);
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),1);

		assertArrayEquals(u.get(DOMAIN1, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2Copy);
		
		//-----------------------------------------
	
		try {
			u.get(DOMAIN2, USER2);
		} catch (Exception e) {
			assert (e instanceof DomainNotFoundException);
		}
		
		try {
			u.get(DOMAIN1, "usernotfoud".getBytes());
		} catch (Exception e) {
			assert (e instanceof UsernameNotFoundException);
		}
		
		// quando inserimos uma pass num domain e username que já existe, ou seja mudamos a pass
		
		u.put(DOMAIN1, USER1, p3);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		assertArrayEquals(u.get(DOMAIN1, USER1), p3Copy);
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN1, USER1), p3Copy);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2Copy);
		
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		assertNull(userNamesDuples);	
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),1);

		//------------------------------

		u.put(DOMAIN2, USER1, p1);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		assertEquals(userTriples.size(),2);
		assertEquals(userNamesDuples.size(),1);
		
		u.put(DOMAIN2, USER2, p2);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		
		assertEquals(userTriples.size(),2);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN2, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN2, USER2), p2Copy);
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),2);
		assertArrayEquals(u.get(DOMAIN2, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN2, USER2), p2Copy);
		
		//-----------------------------------------
	}

	@Test
	public final void testGet() {
		User u = new User(pubKey);
		//-------------------------------------
		try {
			u.get(null, null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		
		try {
			u.get(DOMAIN2, USER1);
		} catch (Exception e) {
			assert (e instanceof DomainNotFoundException);
		}
		
		//-------------------------------------
		//Test size of domains map in user
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),0);

		

		u.put(DOMAIN1, USER1, p1);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),1);
		
		u.put(DOMAIN1, USER2, p2);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN1, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2);
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),1);

		assertArrayEquals(u.get(DOMAIN1, USER1), p1);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2);
		
		//-----------------------------------------
	
		try {
			u.get(DOMAIN2, USER2);
		} catch (Exception e) {
			assert (e instanceof DomainNotFoundException);
		}
		try {
			u.get(DOMAIN2, null);
		} catch (Exception e) {
			assert (e instanceof NullPointerException);
		}
		try {
			u.get(DOMAIN1, "usernotfoud".getBytes());
		} catch (Exception e) {
			assert (e instanceof UsernameNotFoundException);
		}
		
		// quando inserimos uma pass num domain e username que já existe, ou seja mudamos a pass
		
		u.put(DOMAIN1, USER1, p3);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN1));
		assertArrayEquals(u.get(DOMAIN1, USER1), p3Copy);
		assertEquals(userTriples.size(),1);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN1, USER1), p3Copy);
		assertArrayEquals(u.get(DOMAIN1, USER2), p2Copy);
		
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		assertNull(userNamesDuples);	
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),1);

		//------------------------------

		u.put(DOMAIN2, USER1, p1);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		assertEquals(userTriples.size(),2);
		assertEquals(userNamesDuples.size(),1);
		
		u.put(DOMAIN2, USER2, p2);
		
		userTriples = u.getTriples();
		userNamesDuples = userTriples.get( new ByteArrayWrapper(DOMAIN2));
		
		assertEquals(userTriples.size(),2);
		assertEquals(userNamesDuples.size(),2);
		assertArrayEquals(u.get(DOMAIN2, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN2, USER2), p2Copy);
		
		userTriples = u.getTriples();
		assertEquals(userTriples.size(),2);
		assertArrayEquals(u.get(DOMAIN2, USER1), p1Copy);
		assertArrayEquals(u.get(DOMAIN2, USER2), p2Copy);
		
		//-----------------------------------------
	
	}

}
