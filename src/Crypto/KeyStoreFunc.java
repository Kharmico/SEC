package Crypto;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyStoreFunc {
	private KeyStore ks;
	private PasswordProtection ksPassword;
	private static final String ASSYM_K_GEN_ALG = "RSA";
	private static final int ASSYM_K_GEN_BYTES = 2048;
	private static final String PRIVATE_KEY_ALIAS = "privateKey";
	
	public void loadKeyStore(String file, char[] ksPassword)
			throws Exception {
		ks = KeyStore.getInstance("JCEKS");
		this.ksPassword = new PasswordProtection(ksPassword);
		
		java.io.FileOutputStream fos = null;
		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(file);
			ks.load(fis, this.ksPassword.getPassword());
		} catch (FileNotFoundException e) {
			ks.load(null, null);
			fos = new java.io.FileOutputStream(file);
			KeyPair kpair = genKeyPairs();
			X509Certificate[] certif = GenCert.generateCertificate(kpair);
			ks.setKeyEntry(PRIVATE_KEY_ALIAS, kpair.getPrivate().getEncoded(), certif);
			ks.store(fos, this.ksPassword.getPassword());
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
	}
	
	public KeyPair genKeyPairs() throws NoSuchAlgorithmException{
		KeyPairGenerator gen = KeyPairGenerator.getInstance(ASSYM_K_GEN_ALG);
		gen.initialize(ASSYM_K_GEN_BYTES);
		return gen.generateKeyPair();
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
	
	
	private Key getPrivateKey(String alias) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		// get my private key
		//KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(PRIVATE_KEY_ALIAS, this.ksPassword);
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, this.ksPassword);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		return myPrivateKey;
	}
	
	
	public KeyStore getKeyStore(){
		return ks;
	}
	
}
