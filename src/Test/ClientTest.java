package Test;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Hashtable;

import javax.crypto.KeyGenerator;

import org.junit.After;
import org.junit.Before;

import Client.*;
import Server.ByteArrayWrapper;
import Server.Server;

import org.junit.Test;

public class ClientTest {
	private static final char[] KS_PASS = "a26tUfrGg4e4LHX".toCharArray();
	private static final String KS_PAHT = System.getProperty("user.dir") + "\\Resources\\KeyStoreTest.jks";

	@Before
//	public void setUp() {
//		Server s = new Server();
//		String[] = new String [2];
//		s.main(args);
//
//	}

	/**
	 * Tears down the test fixture. (Called after every test case method.)
	 */
	@After
	public void tearDown() {

	}

	@Test
	public void TestServerBoot() {

	}

}
