package Client;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;

import Crypto.CryptoFunctions;
import Crypto.KeyStoreFunc;
import Crypto.Message;
import Exceptions.InvalidSignatureException;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.DestroyFailedException;

//Class com cryptografica
public class ClientManager implements PasswordManager {

	private static final String SERVER_CERT_ALIAS = "servercert";
	private static final String CLIENT_PAIR_ALIAS = "clientPair";
	private static final String CERT_PATH = System.getProperty("user.dir") + "\\Resources\\serversec%s.cer";

	private KeyStore ks = null;
	// private static final String KEY_ALIAS = "serversec";
	PasswordProtection ksPassword = null;
	int bitLength = 1024;
	SecureRandom rnd = new SecureRandom();
	BigInteger p = BigInteger.probablePrime(bitLength, rnd);
	BigInteger g = BigInteger.probablePrime(bitLength, rnd);
	private String deviceId;
	private Map<String, Server> servers;

	public ClientManager(String[] urls) {
		this.servers = new HashMap<String, Server>();
		for (int i = 0; i < urls.length; i++) {
			this.servers.put(urls[i], new ServerClass(urls[i]));
		}
		Random r = new Random();
		int Low = 1;
		int High = 100;
		Integer result = r.nextInt(High - Low) + Low;
		deviceId = new String(Base64.getEncoder().encode(result.toString().getBytes()));
		CryptoFunctions.setJcePolicy();
	}

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
	public void init(KeyStore ks, char[] ksPassword) throws Exception {
		this.ks = ks;
		this.ksPassword = new PasswordProtection(ksPassword);
		for (Server s : servers.values()) {
			URI u = new URI(s.getUrl());
			u.getPort();
			// serverPubKey = KeyStoreFunc.getPublicKey(ks, SERVER_CERT_ALIAS);
			PublicKey serverPubKey = KeyStoreFunc.getPublicKeyCertificate(String.format(CERT_PATH, u.getPort()));
			s.setPubKey(serverPubKey);
		}

	}

	/*
	 * Specification: registers the user on the server, initializing the
	 * required data structures to securely store the passwords.
	 */
	@Override
	public void register_user() throws Exception {

		byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		byte[] hash_nonce = CryptoFunctions.getHashMessage(nonce);
		Message m = new Message(pubk, hash_nonce, deviceId);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);
		for (Server s : servers.values()) {
			
			ClientConnections.register(s.getTarget(),serialized_message, signed_message);
		}

	}

	/*
	 * Specification: stores the triple (domain, username, password) on the
	 * server. This corresponds to an insertion if the (domain, username) pair
	 * is not already known by the server, or to an update otherwise.
	 */
	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws Exception {

		byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		byte[] cypher_p = CryptoFunctions.encrypt_data_asymmetric(password, pubk);
		String salt = this.getSalt();

		byte[] hash_d = CryptoFunctions.getHashMessage((new String(domain) + salt).getBytes());
		byte[] hash_u = CryptoFunctions.getHashMessage((new String(username) + salt).getBytes());
		Message m = new Message(pubk, hash_d, hash_u, cypher_p, nonce, deviceId);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);
		for (Server s : servers.values()) {
			ClientConnections.put(s.getTarget(),serialized_message, signed_message);
		}
	}

	/*
	 * Specification: retrieves the password associated with the given (domain,
	 * username) pair. The behavior of what should happen if the (domain,
	 * username) pair does not exist is unspecified.
	 */
	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws Exception {

		byte[] nonce = CryptoFunctions.generateNonce();
		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		String salt = this.getSalt();
		byte[] hash_d = CryptoFunctions.getHashMessage((new String(domain) + salt).getBytes());
		byte[] hash_u = CryptoFunctions.getHashMessage((new String(username) + salt).getBytes());
		Message m = new Message(pubk, hash_d, hash_u, nonce, deviceId);
		String serialized_message = CryptoFunctions.serialize(m);
		byte[] signed_message = CryptoFunctions.sign_data(serialized_message.getBytes(), privk);
		for (Server s : servers.values()) {
			m = ClientConnections.get(s.getTarget(), serialized_message, signed_message);
			if (!CryptoFunctions.verifySignature(m.getPassword(), m.getPasswordSignature(), s.getPubKey())) {
				throw new InvalidSignatureException();
			}
		}
		return CryptoFunctions.decrypt_data_asymmetric(m.getPassword(), privk);

	}

	@Override
	public void close() throws DestroyFailedException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		KeyStoreFunc.safeStore(ks, ksPassword.getPassword());
		ksPassword.destroy();
		// concludes the current session of commands with the client library.

	}

	private String getSalt() throws KeyStoreException {
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		String aux = Base64.getEncoder().encodeToString(pubk.getEncoded());
		return (String) aux.subSequence(0, Math.min(aux.length(), 10));
	}

}
