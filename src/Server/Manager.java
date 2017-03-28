/**
 * 
 */
package Server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyStore.PasswordProtection;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Crypto.CryptoFunctions;
import Crypto.KeyStoreFunc;
import Exceptions.DomainNotFoundException;
import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;

/**
 * @author paulo
 *
 */
public class Manager {

	private static final String SECRET_KEY_ALIAS = "secretServerKey";
	private static final String SERVER_PAIR_ALIAS = "serversec";

	private static final String KS_PATH = System.getProperty("user.dir") + "\\Resources\\KeyStore.jks";
	public static final String USERS_FILE = System.getProperty("user.dir") + "\\Resources\\Users";

	private static final String CIPHER_ALG = "AES/ECB/PKCS5Padding";

	int bitLength = 1024;
	SecureRandom rnd = new SecureRandom();

	private KeyStore ks;
	private Map<ByteArrayWrapper, User> users;
	private PasswordProtection ksPassword;
	private Map<ByteArrayWrapper, Key> sessionKeys;

	private void serverImpl(char[] password) throws ClassNotFoundException, IOException {
		this.users = new Hashtable<ByteArrayWrapper, User>();
		this.sessionKeys = new Hashtable<ByteArrayWrapper, Key>();

	}

	public Manager(char[] ksPassword) throws Exception {
		this.serverImpl(ksPassword);
		this.ksPassword = new PasswordProtection(ksPassword);
		this.ks = KeyStoreFunc.loadKeyStore(KS_PATH, ksPassword, SERVER_PAIR_ALIAS);
	}
	public Manager(String file, char[] ksPassword) throws Exception {
		this.serverImpl(ksPassword);
		this.ksPassword = new PasswordProtection(ksPassword);
		this.ks = KeyStoreFunc.loadKeyStore(KS_PATH, ksPassword, SERVER_PAIR_ALIAS);
	}

	public Key init(Key pk, Key dhPk, BigInteger g, BigInteger p)
			throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		// Use the values to generate a key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
		DHParameterSpec dhSpec = new DHParameterSpec(p, g);
		keyGen.initialize(dhSpec);
		KeyPair keypair = keyGen.generateKeyPair();

		// Get the generated public and private keys
		Key privateKey = keypair.getPrivate();
		Key publicKey = keypair.getPublic();
		
		System.out.println("DH PUBKEY CLIENT " + new String(Base64.getEncoder().encode(dhPk.getEncoded())));
		// Prepare to generate the secret key with the private key and public
		// key of the other party
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(privateKey);
		ka.doPhase(dhPk, true);

		// Specify the type of key to generate;
		// see Listing All Available Symmetric Key Generators
		String algorithm = "AES";

		// Generate the secret key
		SecretKey secretKey = ka.generateSecret(algorithm);
		ByteArrayWrapper aux=new ByteArrayWrapper(Base64.getEncoder().encode(pk.getEncoded()));
		sessionKeys.put(aux, secretKey);
		return publicKey;
	}

	protected Key getSessionKey(PublicKey clientPk) {
		ByteArrayWrapper aux=new ByteArrayWrapper(Base64.getEncoder().encode(clientPk.getEncoded()));
		return this.sessionKeys.get(aux);
	}

	public void register(Key publicKey) throws UserAlreadyRegisteredException {
		ByteArrayWrapper	pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (this.users.containsKey(pk))
			throw new UserAlreadyRegisteredException();
		this.users.put(pk, new User(pk));
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws UserNotRegisteredException {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		this.users.get(pk).put(domain, username, password);
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username)
			throws UserNotRegisteredException, DomainNotFoundException, UsernameNotFoundException {

		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		return this.users.get(pk).get(domain, username);
	}

	public int usersSize() {
		return this.users.size();
	}

	// OLD STUFF, DIDN'T DELETE JUST IN CASE
	/*
	 * public void safeStore(char[] ksPassword) throws KeyStoreException,
	 * NoSuchAlgorithmException, CertificateException, IOException { // store
	 * away the keystore java.io.FileOutputStream fos = null; try { fos = new
	 * java.io.FileOutputStream("newKeyStoreName"); ks.store(fos, ksPassword); }
	 * finally { if (fos != null) { fos.close(); } }
	 * 
	 * }
	 */

	/*
	 * private void loadKeyStore(String file) throws KeyStoreException,
	 * NoSuchAlgorithmException, CertificateException, IOException { ks =
	 * KeyStore.getInstance(KeyStore.getDefaultType());
	 * 
	 * // java.io.FileInputStream fis = null; try { fis = new
	 * java.io.FileInputStream(file); ks.load(fis,
	 * this.ksPassword.getPassword()); } finally { if (fis != null) {
	 * fis.close(); } } }
	 */
	// ---------------OLD FINITO-------------------------/

	public void writeUsersFiles(SecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, KeyStoreException, FileNotFoundException, IOException {

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = null;
		byte[] cleartext = null;
		try {
			out = new ObjectOutputStream(bos);
			out.writeObject(this.users);
			out.flush();
			cleartext = bos.toByteArray();
		} finally {
			try {
				bos.close();
			} catch (IOException ex) {
				// ignore close exception
			}
		}

		// Initialize cipher object
		Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
		aesCipher.init(Cipher.ENCRYPT_MODE, key);
		// Encrypt the cleartext
		byte[] ciphertext = aesCipher.doFinal(cleartext);

		// write to file
		FileOutputStream o = new FileOutputStream(USERS_FILE);
		o.write(ciphertext);
		o.flush();
		o.close();
	}

	public void readUsersFile(SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
		Map<ByteArrayWrapper, User> users = null;
		try {
			Path path = Paths.get(USERS_FILE);
			byte[] ciphertext = Files.readAllBytes(path);

			Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
			// Initialize the same cipher for decryption
			aesCipher.init(Cipher.DECRYPT_MODE, key);
			// Decrypt the ciphertext
			byte[] cleartext = aesCipher.doFinal(ciphertext);
			ByteArrayInputStream in = new ByteArrayInputStream(cleartext);

			ObjectInputStream is = new ObjectInputStream(in);
			users = (Hashtable<ByteArrayWrapper, User>) is.readObject();
			in.close();
		} catch (IOException i) {
			users = new Hashtable<ByteArrayWrapper, User>();
		} finally {
			this.users = users;
		}

	}
	protected Key getServerPrivateKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
		return KeyStoreFunc.getPrivateKey(ks, SERVER_PAIR_ALIAS, ksPassword);
	}

	// //guardar uma secret key - dá Cannot store non private keys
	// public void storeSecretKey(SecretKey key) throws KeyStoreException,
	// NoSuchAlgorithmException, CertificateException,
	// FileNotFoundException, IOException {
	//
	// KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
	//
	// // Store our secret key
	// ks.setEntry(SECRET_KEY_ALIAS, keyStoreEntry, this.ksPassword);
	// ks.store(new FileOutputStream(KS_PAHT), this.ksPassword.getPassword());
	//
	// }
	//
	// public SecretKey retrieveKey() throws NoSuchAlgorithmException,
	// UnrecoverableEntryException, KeyStoreException {
	//
	// //Retrieve the entry from the keystore
	// KeyStore.Entry entry = ks.getEntry(SECRET_KEY_ALIAS, this.ksPassword);
	//
	// //Assign the entry as our secret key for later retrieval.
	// SecretKey key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
	//
	// return key;
	// }

}
