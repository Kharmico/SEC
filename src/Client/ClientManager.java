package Client;

import java.io.IOException;
import java.math.BigInteger;
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
import Server.ByteArrayWrapper;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

//Class com cryptografica
public class ClientManager implements PasswordManager {

	private KeyStore ks = null;
	// private static final String KEY_ALIAS = "serversec";
	private static final String SERVER_CERT_ALIAS = "servercert";
	// private static final byte[] MASTER_KEY =
	// Base64.getDecoder().decode("/SJpodDfXUbZB4u119dKQg==".getBytes());
	private static SecretKey sessionKey;
	private static final String CLIENT_PAIR_ALIAS = "clientPair";
	// char[] _ksPassword = null;
	ClientConnections clientconn = null;
	PasswordProtection ksPassword = null;
	int bitLength = 1024;
	SecureRandom rnd = new SecureRandom();
	BigInteger p = BigInteger.probablePrime(bitLength, rnd);
	BigInteger g = BigInteger.probablePrime(bitLength, rnd);
	
	private static  SecretKey MASTER_KEY;

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
	public void init(KeyStore ks, char[] ksPassword) throws NoSuchAlgorithmException, ClassNotFoundException,
			IOException, UnrecoverableEntryException, KeyStoreException, SignatureException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {
		this.ks = ks;
		this.ksPassword = new PasswordProtection(ksPassword);
		clientconn = new ClientConnections();
		MASTER_KEY = (SecretKey) CryptoFunctions.desSerialize(
				"rO0ABXNyAB9qYXZheC5jcnlwdG8uc3BlYy5TZWNyZXRLZXlTcGVjW0cLZuIwYU0CAAJMAAlhbGdvcml0aG10ABJMamF2YS9sYW5nL1N0cmluZztbAANrZXl0AAJbQnhwdAADQUVTdXIAAltCrPMX+AYIVOACAAB4cAAAABCJzON5PSWnsYxFrxWAd1dA");

//diffie-helman
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
//		DHParameterSpec dhSpec = new DHParameterSpec(p , g);
//		keyGen.initialize(dhSpec);
//		KeyPair keypair = keyGen.generateKeyPair();
//
//		// Get the generated public and private keys
//		PrivateKey privateKey = (DHPrivateKey) keypair.getPrivate();
//		PublicKey publicKey = (DHPublicKey) keypair.getPublic();
//
//		// Send the public key bytes to the other party...
////		byte[] publicKeyBytes = publicKey.getEncoded();
//
//		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
//		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, this.ksPassword);
//		String serialize_pk = CryptoFunctions.serialize(pubk);
//		byte[] signature = CryptoFunctions.sign_data(serialize_pk.getBytes(), privk);
//		// Retrieve the public key bytes of the other party
//		byte[] clientPk = Base64.getDecoder().decode(clientconn.init(serialize_pk, signature,CryptoFunctions.serialize(publicKey)));
//
////		publicKey=(DHPublicKey) CryptoFunctions.desSerialize(clientPk);
//		// Convert the public key bytes into a PublicKey object
//		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPk);
//		KeyFactory keyFact = KeyFactory.getInstance("DH");
//		publicKey = keyFact.generatePublic(x509KeySpec);
//
//		// Prepare to generate the secret key with the private key and public
//		// key of the other party
//		KeyAgreement ka = KeyAgreement.getInstance("DH");
//		ka.init(privateKey);
//		ka.doPhase(publicKey, true);
//
//		// Specify the type of key to generate;
//		// see Listing All Available Symmetric Key Generators
//		String algorithm = "DES";
//
//		// Generate the secret key
//		SecretKey secretKey = ka.generateSecret(algorithm);
//
//		
//
//		// KeyAgreement ka = KeyAgreement.getInstance("DH");
//		// ka.init(KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS,
//		// this.ksPassword));
//		// ka.doPhase(KeyStoreFunc.getPublicKey(ks, SERVER_CERT_ALIAS),true);
//		// byte[] secrectKey= ka.generateSecret();
//		// sessionKey = new SecretKeySpec(secrectKey, "AES");
//		//
//		// PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
//		// PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS,
//		// this.ksPassword);
//		// String serialize_pk = CryptoFunctions.serialize(pubk);
//		// byte[] signature = CryptoFunctions.sign_data(serialize_pk.getBytes(),
//		// privk);

	}

	/*
	 * Specification: registers the user on the server, initializing the
	 * required data structures to securely store the passwords.
	 */
	@Override
	public void register_user() throws Exception {

		// Get the public key to send!!!
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		String serialize_pk = CryptoFunctions.serialize(pubk);
		byte[] signature = CryptoFunctions.sign_data(serialize_pk.getBytes(), privk);

		clientconn.register(serialize_pk, signature);

	}

	/*
	 * Specification: stores the triple (domain, username, password) on the
	 * server. This corresponds to an insertion if the (domain, username) pair
	 * is not already known by the server, or to an update otherwise.
	 */
	@Override
	public void save_password(byte[] domain, byte[] username, byte[] password) throws Exception {

		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		// Key superKey = new SecretKeySpec(MASTER_KEY, "AES");

		String serialize_pk = CryptoFunctions.serialize(pubk);
		// String cypher_d = CryptoFunctions.encrypt_data_asymmetric(new
		// String(domain), pubk);
		// String cypher_u = CryptoFunctions.encrypt_data_asymmetric(new
		// String(username), pubk);
		byte[] cypher_p = CryptoFunctions.encrypt_data_asymmetric(password, pubk);

		byte[] hash_d = CryptoFunctions.getHashMessage(domain);
		byte[] hash_u = CryptoFunctions.getHashMessage(username);

		byte[] s_pubKey = CryptoFunctions.sign_data(serialize_pk.getBytes(), privk);
		byte[] s_domain = CryptoFunctions.sign_data(hash_d, privk);
		byte[] s_username = CryptoFunctions.sign_data(hash_u, privk);
		byte[] s_password = CryptoFunctions.sign_data(cypher_p, privk);

//		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, sessionKey);
//		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, sessionKey);
//		s_password = CryptoFunctions.encrypt_data_symmetric(s_password, sessionKey);
//		hash_d = CryptoFunctions.encrypt_data_symmetric(hash_d, sessionKey);
//		hash_u = CryptoFunctions.encrypt_data_symmetric(hash_u, sessionKey);
//		cypher_p = CryptoFunctions.encrypt_data_symmetric(cypher_p, sessionKey);
		
		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, MASTER_KEY);
		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, MASTER_KEY);
		s_password = CryptoFunctions.encrypt_data_symmetric(s_password, MASTER_KEY);
		hash_d = CryptoFunctions.encrypt_data_symmetric(hash_d, MASTER_KEY);
		hash_u = CryptoFunctions.encrypt_data_symmetric(hash_u, MASTER_KEY);
		cypher_p = CryptoFunctions.encrypt_data_symmetric(cypher_p, MASTER_KEY);
		
	

		clientconn.put(serialize_pk, s_pubKey, hash_d, s_domain, hash_u, s_username, cypher_p, s_password);
	}

	/*
	 * Specification: retrieves the password associated with the given (domain,
	 * username) pair. The behavior of what should happen if the (domain,
	 * username) pair does not exist is unspecified.
	 */
	@Override
	public byte[] retrieve_password(byte[] domain, byte[] username) throws Exception {

		// Get the public key to send!!!
		PrivateKey privk = KeyStoreFunc.getPrivateKey(ks, CLIENT_PAIR_ALIAS, ksPassword);
		PublicKey pubk = KeyStoreFunc.getPublicKey(ks, CLIENT_PAIR_ALIAS);
		// Key superKey = new SecretKeySpec(MASTER_KEY, "AES");

		String serialize_pk = CryptoFunctions.serialize(pubk);
		// String cypher_d = CryptoFunctions.encrypt_data_asymmetric(new
		// String(domain), pubk);
		// String cypher_u = CryptoFunctions.encrypt_data_asymmetric(new
		// String(username), pubk);

		byte[] hash_d = CryptoFunctions.getHashMessage(domain);
		byte[] hash_u = CryptoFunctions.getHashMessage(username);

		byte[] s_pubKey = CryptoFunctions.sign_data(serialize_pk.getBytes(), privk);
		byte[] s_domain = CryptoFunctions.sign_data(hash_d, privk);
		byte[] s_username = CryptoFunctions.sign_data(hash_u, privk);
		
//		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, sessionKey);
//		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, sessionKey);
//
//		hash_d = CryptoFunctions.encrypt_data_symmetric(hash_d, sessionKey);
//		hash_u = CryptoFunctions.encrypt_data_symmetric(hash_u, sessionKey);
		
		s_domain = CryptoFunctions.encrypt_data_symmetric(s_domain, MASTER_KEY);
		s_username = CryptoFunctions.encrypt_data_symmetric(s_username, MASTER_KEY);

		hash_d = CryptoFunctions.encrypt_data_symmetric(hash_d, MASTER_KEY);
		hash_u = CryptoFunctions.encrypt_data_symmetric(hash_u, MASTER_KEY);

		// Get the public key to send!!!
		byte[] rowPassword = clientconn.get(serialize_pk, s_pubKey, hash_d, s_domain, hash_u, s_username);

//		byte[] password = CryptoFunctions.decrypt_data_symmetric(rowPassword, sessionKey);
		byte[] password = CryptoFunctions.decrypt_data_symmetric(rowPassword, MASTER_KEY);
		byte[] p2 = CryptoFunctions.decrypt_data_asymmetric(password, privk);
		String a = new String(p2);
		return p2;

	}

	@Override
	public void close() throws DestroyFailedException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException {

		KeyStoreFunc.safeStore(ks, ksPassword.getPassword());
		ksPassword.destroy();
		// concludes the current session of commands with the client library.

	}

}
