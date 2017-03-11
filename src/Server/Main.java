/**
 * 
 */
package Server;

import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;

/**
 * @author paulo
 *
 */
public class Main {

	/**
	 * 
	 * @param args
	 *            keyStore password
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	public static void main(String[] args)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
	
		Server s = null;
		if (args.length == 2) {

			s = new ServerImpl(args[0].toCharArray());
		} else {
			s = new ServerImpl(args[1], args[0].toCharArray());
		}
		// listening

		// stopserver
	}

}
