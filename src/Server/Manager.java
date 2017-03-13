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
import java.security.KeyStore.PasswordProtection;
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
import javax.crypto.spec.SecretKeySpec;

import org.omg.CORBA.Context;

import Exceptions.DomainNotFoundException;
import Exceptions.UserAlreadyRegisteredException;
import Exceptions.UserNotRegisteredException;
import Exceptions.UsernameNotFoundException;

/**
 * @author paulo
 *
 */
public class Manager  {

	public static final String PRIVATE_KEY_ALIAS = "privateServerKey";
	private static final String SECRET_KEY_ALIAS = "secretServerKey";

	private static final String KS_PAHT = System.getProperty("user.dir") + "\\Resources\\KeyStore.jks";
	public static final String USERS_FILE = System.getProperty("user.dir") + "\\Resources\\Users";
	

	private static final String CIPHER_ALG = "AES/ECB/PKCS5Padding";

	private KeyStore ks;
	private Map<ByteArrayWrapper, User> users;
	private PasswordProtection ksPassword;

	private void serverImpl(char[] password) {
		this.users = new Hashtable<ByteArrayWrapper, User>();
		this.ksPassword = new PasswordProtection(password);
	}

	public Manager(char[] ksPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.serverImpl(ksPassword);
		loadKeyStore(KS_PAHT);
	}

	public Manager(String file, char[] ksPassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		this.serverImpl(ksPassword);
		loadKeyStore(file);

	}

	
	public void register(Key publicKey) throws UserAlreadyRegisteredException {
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (this.users.containsKey(pk))
			throw new UserAlreadyRegisteredException();
		this.users.put(pk, new User(pk));
	}

	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws UserNotRegisteredException{
		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		this.users.get(pk).put(domain, username, password);
	}

	
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws UserNotRegisteredException,DomainNotFoundException,UsernameNotFoundException {

		ByteArrayWrapper pk = new ByteArrayWrapper(Base64.getEncoder().encode(publicKey.getEncoded()));
		if (!this.users.containsKey(pk))
			throw new UserNotRegisteredException();
		return this.users.get(pk).get(domain, username);
	}

	public int usersSize() {
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

	private void loadKeyStore(String file)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());

		//
		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(file);
			ks.load(fis, this.ksPassword.getPassword());
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}

	private Key getPrivateKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		// get my private key
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(PRIVATE_KEY_ALIAS, this.ksPassword);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		return myPrivateKey;
	}

	public boolean hasKs() {
		return this.ks != null;
	}

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
	
//	//guardar uma secret key - dá Cannot store non private keys
//		public void storeSecretKey(SecretKey key) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
//				FileNotFoundException, IOException {
//			
//			KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
//
//			// Store our secret key
//			ks.setEntry(SECRET_KEY_ALIAS, keyStoreEntry, this.ksPassword);
//			ks.store(new FileOutputStream(KS_PAHT), this.ksPassword.getPassword());
//
//		}
//		
//		public SecretKey retrieveKey() throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
//
//		    //Retrieve the entry from the keystore
//		    KeyStore.Entry entry = ks.getEntry(SECRET_KEY_ALIAS, this.ksPassword);
//
//		    //Assign the entry as our secret key for later retrieval.
//		    SecretKey key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
//
//		    return key;
//		}

}
