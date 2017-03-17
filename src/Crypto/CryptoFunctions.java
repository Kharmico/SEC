package Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.PrivateKey;

public class CryptoFunctions {
	private static final String ASSYM_K_GEN_ALG = "RSA";
	private static final int ASSYM_K_GEN_BYTES = 2048;
	
	
	public static byte[] decrypt_data_symmetric(String encData,Key k)
	        throws NoSuchAlgorithmException, NoSuchPaddingException,
	        InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.DECRYPT_MODE, k);

	    System.out.println("Base64 decoded: "+ Base64.getDecoder().decode(encData.getBytes()).length);
	    return cipher.doFinal(Base64.getDecoder().decode(encData.getBytes()));
//	    return new String(original).trim();
	}
	public static byte[] decrypt_data_asymmetric(String encData,Key k)
	        throws NoSuchAlgorithmException, NoSuchPaddingException,
	        InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    
	    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    cipher.init(Cipher.DECRYPT_MODE, k);

	    System.out.println("Base64 decoded: "+ Base64.getDecoder().decode(encData.getBytes()).length);
	    return cipher.doFinal(Base64.getDecoder().decode(encData.getBytes()));
//	    return new String(original).trim();
	}
	public static String encrypt_data_symmetric(String data,Key k) throws Exception {
	    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, k);
	    System.out.println("Base64 encoded: "+ Base64.getEncoder().encode(data.getBytes()).length);

	    byte[] original = Base64.getEncoder().encode(cipher.doFinal(data.getBytes()));
	    return new String(original);
	}
	
	public static String encrypt_data_asymmetric(String data,Key k) throws Exception {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, k);
	    System.out.println("Base64 encoded: "+ Base64.getEncoder().encode(data.getBytes()).length);

	    byte[] original = Base64.getEncoder().encode(cipher.doFinal(data.getBytes()));
	    return new String(original);
	}
	
	
	public static byte[] sign_data(byte[] data, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException{
//		byte [] content = data.getBytes(); 
		// generating a signature
		Signature dsaForSign = Signature.getInstance("SHA1withRSA"); 
		dsaForSign.initSign(key); 
		dsaForSign.update(data); 
		return dsaForSign.sign(); 
		
	}
	
	public static boolean verifySignature(byte[] data, byte[] signature, PublicKey key) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException{
		Signature dsaForVerify = Signature.getInstance("SHA1withRSA"); 
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
	
	public static Object desSerialize(String obj) throws ClassNotFoundException, IOException {
		ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode((obj.getBytes())));
		ObjectInputStream is = new ObjectInputStream(in);
		return is.readObject();
	}
	public static String serialize(Serializable o) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(o);
		oos.close();
		return Base64.getEncoder().encodeToString(baos.toByteArray());
	}
	public static Key genKey() {
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		}
		keyGen.init(128); // for example
		return keyGen.generateKey();
	}
	public static KeyPair genKeyPairs() throws NoSuchAlgorithmException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance(ASSYM_K_GEN_ALG);
		gen.initialize(ASSYM_K_GEN_BYTES);
		return gen.generateKeyPair();
	}
	
	
}
