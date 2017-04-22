package Crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class KeyStoreFunc {
	// private KeyStore ks;
	// private PasswordProtection ksPassword;

	// private static final String KEY_ALIAS = "serversec";
	public static PublicKey getPublicKeyCertificate(String path) throws FileNotFoundException, CertificateException {
		FileInputStream fin = new FileInputStream(path);
		CertificateFactory f = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
		return certificate.getPublicKey();

	}

	public static KeyStore loadKeyStore(String file, char[] ksPassword, String alias) throws Exception {
		KeyStore ks = KeyStore.getInstance("JKS");
		// this.ksPassword = new PasswordProtection(ksPassword);

		java.io.FileOutputStream fos = null;
		java.io.FileInputStream fis = null;
		try {
			fis = new java.io.FileInputStream(file);
			// ks.load(fis, this.ksPassword.getPassword());
			ks.load(fis, ksPassword);
		} catch (FileNotFoundException e) {
			ks.load(null, null);
			fos = new java.io.FileOutputStream(file);
			KeyPair kpair = CryptoFunctions.genKeyPairs();
			X509Certificate[] certif = GenCert.generateCertificate(kpair);
			ks.setKeyEntry(alias, kpair.getPrivate(), ksPassword, certif);
			// ks.store(fos, this.ksPassword.getPassword());
			ks.store(fos, ksPassword);
		} finally {
			if (fis != null) {
				fis.close();
			}
		}
		return ks;
	}

	public static void safeStore(KeyStore ks, char[] ksPassword)
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

	public static PrivateKey getPrivateKey(KeyStore ks, String alias, PasswordProtection ksPassword)
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		// get my private key
		// KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
		// ks.getEntry(PRIVATE_KEY_ALIAS, this.ksPassword);
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, ksPassword);
		PrivateKey myPrivateKey = pkEntry.getPrivateKey();
		byte[] aux = myPrivateKey.getEncoded();
		String a = new String (aux);
		String b = Base64.getEncoder().encodeToString(aux);
		return myPrivateKey;
	}

	public static PublicKey getPublicKey(KeyStore ks, String certificateAlias) throws KeyStoreException {
		Certificate cert = ks.getCertificate(certificateAlias);
		return cert.getPublicKey();
	}

	

	// public KeyStore getKeyStore(){
	// return ks;
	// }

}
