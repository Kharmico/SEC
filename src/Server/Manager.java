/**
 * 
 */
package Server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
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
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

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
import Crypto.Password;
import Exceptions.DomainNotFoundException;
import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;

/**
 * @author paulo
 *
 */
public class Manager {

	private static final String SERVER_PAIR_ALIAS = "serversec";
	private static final String KS_PATH = System.getProperty("user.dir") + "/Resources/KeyStore%s.jks";
	public static final String USERS_FILE = System.getProperty("user.dir") + "/Resources/%s/Users";
	public static final String DIR_PATH = System.getProperty("user.dir") + "/Resources/";
	private static final String CIPHER_ALG = "AES/ECB/PKCS5Padding";
	private static String dirPath;
	private static String usersFile;
	
	int bitLength = 1024;
	SecureRandom rnd = new SecureRandom();

	private KeyStore ks;
	private ConcurrentMap<ByteArrayWrapper, User> users;
	private PasswordProtection ksPassword;

	private void manegerImpl(char[] password) throws ClassNotFoundException, IOException {
		this.users = new ConcurrentHashMap<ByteArrayWrapper, User>();
		this.ksPassword = new PasswordProtection(password);
	}

	public Manager(char[] ksPassword,int port) throws Exception {
		this.manegerImpl(ksPassword);
		String ksPath =String.format(KS_PATH, port);
		dirPath = DIR_PATH.concat(String.valueOf(port));
		usersFile = String.format(USERS_FILE, String.valueOf(port));
		File directory = new File(dirPath);
		if(!directory.exists())
			directory.mkdir();

		this.ks = KeyStoreFunc.loadKeyStore(ksPath, ksPassword, SERVER_PAIR_ALIAS);
	}
	
	public Manager(String file, char[] ksPassword,int port) throws Exception {
		this.manegerImpl(ksPassword);		
		this.ks = KeyStoreFunc.loadKeyStore(file, ksPassword, SERVER_PAIR_ALIAS);
	}
	
	public void register(Key publicKey) throws UserAlreadyRegisteredException {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
//		if (this.users.containsKey(pk))
//			throw new UserAlreadyRegisteredException();
		this.users.put(pk, new User(pk));
	}

	public void put(Key publicKey, byte[] domain, byte[] username, Password password) throws UserNotRegisteredException {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		this.users.get(pk).put(domain, username, password);
	}

	public Password get(Key publicKey, byte[] domain, byte[] username)
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

	public void writeUsersFiles()
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

		// write to file
		FileOutputStream o = new FileOutputStream(usersFile);
		o.write(cleartext);
		o.flush();
		o.close();
	}

	public void readUsersFile() throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException {
		ConcurrentMap<ByteArrayWrapper, User> users = null;
		try {
			Path path = Paths.get(usersFile);
			byte[] cleartext = Files.readAllBytes(path);

			ByteArrayInputStream in = new ByteArrayInputStream(cleartext);

			ObjectInputStream is = new ObjectInputStream(in);
			users = (ConcurrentHashMap<ByteArrayWrapper, User>) is.readObject();
			in.close();
		} catch (IOException i) {
			System.out.println("File not found!");
			users = new ConcurrentHashMap<ByteArrayWrapper, User>();
		} finally {
			this.users = users;
		}

	}
	protected PrivateKey getServerPrivateKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
		return KeyStoreFunc.getPrivateKey(ks, SERVER_PAIR_ALIAS, ksPassword);
	}
	protected PublicKey getServerPublicKeyKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
		return KeyStoreFunc.getPublicKey(ks, SERVER_PAIR_ALIAS);
	}

	// //guardar uma secret key - da Cannot store non private keys
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
