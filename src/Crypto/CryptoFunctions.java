package Crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CryptoFunctions {
	
	private PublicKey publicKey;
	//private PrivateKey privateKey;
	
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
	
	public static byte[] sign_data(String data, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		byte [] content = data.getBytes(); 
		// generating a signature
		Signature dsaForSign = Signature.getInstance("SHA1withDSA"); 
		dsaForSign.initSign(key); 
		dsaForSign.update(content); 
		return dsaForSign.sign(); 
		
	}
	
	public static boolean verifySignature(byte[] data, byte[] signature, PublicKey key) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException{
		Signature dsaForVerify = Signature.getInstance("SHA1withDSA"); 
		dsaForVerify.initVerify(key); 
		dsaForVerify.update(data); 
		return dsaForVerify.verify(signature); 
		//System.out.println("Signature verifies: " + verifies); 
	}
}
