package Crypto;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.CertificateException;

public class KeyStoreFunc {
	private KeyStore ks;
	private PasswordProtection ksPassword;
	
	public void loadKeyStore(String file)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		ks = KeyStore.getInstance("JCEKS");

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
	
	public KeyStore getKeyStore(){
		return ks;
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
	
	public PasswordProtection getPasswordKs(){
		return ksPassword;
	}
	
}
