package Crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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

	public static String encrypt_data(String data) throws Exception {
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
	
	private static byte[] hash_message(String message) throws NoSuchAlgorithmException{
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] messageBytes = message.getBytes();
		digest.update(messageBytes);
		byte[] hash = digest.digest();
		return Base64.getEncoder().encode(hash);
	}
	
	//may need to convert hex to string in hash_message
	private static String convertByteArrayToHexString(byte[] arrayBytes){
		StringBuffer stringBuffer = new StringBuffer();
		for(int i = 0; i < arrayBytes.length; i++)
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16).substring(1));
		return stringBuffer.toString();
	}
	
	//getter for hash_message
	public static byte[] getHashMessage(String message) throws NoSuchAlgorithmException{
		return hash_message(message);
	}
	
	//client should calculate the checksum of file it is sending,
	//send the checksum value with the request as param
	//server side: checksum should be compared against the checksum sent by the client
	//if the two match file is good
	
	//integrity check for a file
	public static byte[] checkFileIntegrity(String filename) throws NoSuchAlgorithmException, IOException{
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		FileInputStream file = new FileInputStream(filename);
		byte[] dataBytes = new byte[1024];
		
		int toRead = 0;
		while((toRead = file.read(dataBytes)) != -1){
			digest.update(dataBytes, 0, toRead);
		}
		byte[] hash = digest.digest();
		return Base64.getEncoder().encode(hash);
	}
	
	
}
