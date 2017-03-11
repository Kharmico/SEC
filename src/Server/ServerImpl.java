/**
 * 
 */
package Server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Hashtable;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;

/**
 * @author paulo
 *
 */
public class ServerImpl implements Server {

	public static final String KEY_ALIAS = "privateServerKey";
	private static final String SECRET_KEY = "secretServerKey";
	private static final String KS_PAHT = System.getProperty("user.dir") + "\\Resources\\KeyStore.jks";
	private static final String USERS_FILE = System.getProperty("user.dir") + "\\Resources\\Users";
	private static final int PORT = 4444;

	private static final String CIPHER_ALG = "AES/ECB/PKCS5Padding";

	private KeyStore ks;
	private KeyStore.ProtectionParameter protParam;
	private Map<ByteArrayWrapper, User> users;

	private void serverImpl() {
		this.users = new Hashtable<ByteArrayWrapper, User>();
	}

	public ServerImpl(char[] ksPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.serverImpl();
		loadKeyStore(ksPassword, KS_PAHT);
	}

	public ServerImpl(String file, char[] ksPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.serverImpl();
		loadKeyStore(ksPassword, file);

	}

	@Override
	public void register(Key publicKey) {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (this.users.containsKey(pk))
			throw new UserAlreadyRegisteredException();
		this.users.put(pk, new User(pk));
	}

	@Override
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		this.users.get(pk).put(domain, username, password);
	}

	@Override
	public byte[] get(Key publicKey, byte[] domain, byte[] username) {

		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		return this.users.get(pk).get(domain, username);
	}
	
	public int usersSize(){
		return this.users.size();
	}

	public void safeStore(char[] ksPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		// store away the keystore
		java.io.FileOutputStream fos = null;
		try {
			fos = new java.io.FileOutputStream("newKeyStoreName");
			ks.store(fos, ksPassword);
		} finally {
			if (fos != null) {
				fos.close();
			}
		}

	}

	private void loadKeyStore(char[] password, String file)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());

		//
		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(file);
			ks.load(fis, password);
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
		protParam = new KeyStore.PasswordProtection(password);
	}

	private Key getPrivateKey(String alias)
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		// get my private key
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		return myPrivateKey;
	}

	public KeyStore getKs() {
		return this.ks;
	}

	// private void genSecretKey(){
	// // create new key and adds it to KS
	// KeyGenerator kgen = KeyGenerator.getInstance("AES");
	// kgen.init(128);
	// SecretKey secretKey = kgen.generateKey();
	// KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry
	// (SECRET_KEY,secretKey);
	// this.ks.setEntry("aliasKey",secretKey,protParam);
	// }

	// private void writeUsersFiles(SecretKey key)
	// throws NoSuchAlgorithmException, NoSuchPaddingException,
	// InvalidKeyException, IllegalBlockSizeException,
	// BadPaddingException, KeyStoreException, FileNotFoundException,
	// IOException {
	// // KeyGenerator keygen = KeyGenerator.getInstance("AES");
	// // keygen.init(128); // initialize the key size
	// // SecretKey aesKey = keygen.generateKey();
	//
	// ByteArrayOutputStream bos = new ByteArrayOutputStream();
	// ObjectOutput out = null;
	// byte[] cleartext =null;
	// try {
	// out = new ObjectOutputStream(bos);
	// out.writeObject(this.users);
	// out.flush();
	// cleartext = bos.toByteArray();
	// } finally {
	// try {
	// bos.close();
	// } catch (IOException ex) {
	// // ignore close exception
	// }
	// }
	//
	// // Initialize cipher object
	// Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
	// aesCipher.init(Cipher.ENCRYPT_MODE, key);
	// // Encrypt the cleartext
	// byte[] ciphertext = aesCipher.doFinal(cleartext);
	//
	// //write to file
	// FileOutputStream o=new FileOutputStream(USERS_FILE);
	// o.write(ciphertext);
	// o.flush();
	// o.close();
	// }

	// private void readUsersFile(){
	// Map<Key, User> users = null;
	// try {
	// Path path = Paths.get("USERS_FILE");
	// byte[] ciphertext = Files.readAllBytes(path);
	//
	// Cipher aesCipher = Cipher.getInstance(CIPHER_ALG);
	// // Initialize the same cipher for decryption
	// aesCipher.init(Cipher.DECRYPT_MODE, key);
	// // Decrypt the ciphertext
	// byte[] cleartext = aesCipher.doFinal(ciphertext);
	// ByteArrayInputStream in = new ByteArrayInputStream(cleartext);
	// ObjectInputStream is = new ObjectInputStream(in);
	// users= (Map<Key, User>) is.readObject();
	// } catch (IOException i) {
	// users = this.users = new Hashtable<Key, User>();
	// }
	//
	// }

}
