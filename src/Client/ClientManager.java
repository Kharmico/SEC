package Client;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;

import Crypto.CryptoFunctions;
import Crypto.KeyStoreFunc;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

//Class com cryptografica
public class ClientManager implements PasswordManager {

	private KeyStore ks = null;
	private static final String KEY_ALIAS = "serversec";
	private static final byte[] MASTER_KEY = Base64.getDecoder().decode("/SJpodDfXUbZB4u119dKQg==".getBytes());

	// char[] _ksPassword = null;
	ClientConnections clientconn = null;
	PasswordProtection ksPassword = null;

	/*
	 * Specification: initializes the library before its first use. This method
	 * should receive a reference to a key store that must contain the private
	 * and public key of the user, as well as any other parameters needed to
	 * access this key store (e.g., its password) and to correctly initialize
	 * the cryptographic primitives used at the client side. These keys
	 * maintained by the key store will be the ones used in the following
	 * session of commands issued at the client side, until a close() function
	 * is called.
	 */
	@Override
	public void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException {
		this.ks = ks;
		this.ksPassword = new PasswordProtection(ksPassword);
		clientconn = new ClientConnections();

	}

	/*
	 * Specification: registers the user on the server, initializing the
	 * required data structures to securely store the passwords.
	 */
	@Override
	public void register_user() throws Exception {

		// Get the public key to send!!!
		PublicKey pk = KeyStoreFunc.getPublicKey(ks, KEY_ALIAS);
//		Key superKey = new SecretKeySpec(MASTER_KEY, "AES");
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, KEY_ALIAS, ksPassword);
		String s_pk=CryptoFunctions.serialize(pk);
		byte[] signature = CryptoFunctions.sign_data(s_pk.getBytes(), privk);
//		s_pk=CryptoFunctions.encrypt_data(s_pk, superKey);
		clientconn.register(s_pk,new String(signature));

	}

	/*
	 * Specification: stores the triple (domain, username, password) on the
	 * server. This corresponds to an insertion if the (domain, username) pair
	 * is not already known by the server, or to an update otherwise.
	 */
	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws Exception {

		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, KEY_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, KEY_ALIAS);
		Key superKey = new SecretKeySpec(MASTER_KEY, "AES");
		
		String s_pk=CryptoFunctions.serialize(pubk);	
		String cypher_d = CryptoFunctions.encrypt_data_asymmetric(new String(domain), pubk);
		String cypher_u = CryptoFunctions.encrypt_data_asymmetric(new String(username), pubk);
		String cypher_p = CryptoFunctions.encrypt_data_asymmetric(new String (password), pubk);
		
		String s_pubKey = new String(CryptoFunctions.sign_data(s_pk.getBytes(), privk));
		String s_domain = new String(CryptoFunctions.sign_data(cypher_d.getBytes(), privk));
		String s_username = new String(CryptoFunctions.sign_data(cypher_u.getBytes(), privk));
		String s_password = new String(CryptoFunctions.sign_data(cypher_p.getBytes(), privk));
			
		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, superKey);
		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, superKey);
		s_password = CryptoFunctions.encrypt_data_symmetric(s_password, superKey);
		
		clientconn.put(s_pk,s_pubKey,cypher_d, s_domain,cypher_u, s_username,s_password, s_password);
	}

	/*
	 * Specification: retrieves the password associated with the given (domain,
	 * username) pair. The behavior of what should happen if the (domain,
	 * username) pair does not exist is unspecified.
	 */
	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws Exception {

		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, KEY_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, KEY_ALIAS);
		Key superKey = new SecretKeySpec(MASTER_KEY, "AES");
		
		String s_pk=CryptoFunctions.serialize(pubk);	
		String cypher_d = CryptoFunctions.encrypt_data_asymmetric(new String(domain), pubk);
		String cypher_u = CryptoFunctions.encrypt_data_asymmetric(new String(username), pubk);
		
		
		String s_pubKey = new String(CryptoFunctions.sign_data(s_pk.getBytes(), privk));
		String s_domain = new String(CryptoFunctions.sign_data(cypher_d.getBytes(), privk));
		String s_username = new String(CryptoFunctions.sign_data(cypher_u.getBytes(), privk));
	
			
		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, superKey);
		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, superKey);
		
		// Get the public key to send!!!
		String rowPassword = clientconn.get(s_pk,s_pubKey,cypher_d, s_domain,cypher_u, s_username);

		byte[] password = CryptoFunctions.decrypt_data_symmetric(rowPassword, superKey);
		return CryptoFunctions.decrypt_data_asymmetric(new String(password), privk);

	}

	@Override
	public void close() throws DestroyFailedException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		KeyStoreFunc.safeStore(ks, ksPassword.getPassword());
		ksPassword.destroy();
		// concludes the current session of commands with the client library.

	}

}
