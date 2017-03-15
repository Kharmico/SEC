package Crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class CryptoFunctions {
	
	public static String decrypt_data(String encData)
	        throws NoSuchAlgorithmException, NoSuchPaddingException,
	        InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    String key = "bad8deadcafef00d"; //use simetric key
	    SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
	    Cipher cipher = Cipher.getInstance("AES");

	    cipher.init(Cipher.DECRYPT_MODE, skeySpec);

	    System.out.println("Base64 decoded: "
	            + Base64.getDecoder().decode(encData.getBytes()).length);
	    byte[] original = cipher
	            .doFinal(Base64.getDecoder().decode(encData.getBytes()));
	    return new String(original).trim();
	}

	public static String encrypt_data(String data)
	        throws Exception {
	    String key = "bad8deadcafef00d";
	    SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
	    Cipher cipher = Cipher.getInstance("AES");

	    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

	    System.out.println("Base64 encoded: "
	            + Base64.getEncoder().encode(data.getBytes()).length);

	    byte[] original = Base64.getEncoder().encode(cipher.doFinal(data.getBytes()));
	    return new String(original);
	}
}
