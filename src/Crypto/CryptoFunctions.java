package Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import java.security.PrivateKey;

public class CryptoFunctions {
	private static final String ASSYM_K_GEN_ALG = "RSA";
	private static final int ASSYM_K_GEN_BYTES = 2048;
	private static final int IV_SIZE = 16;

//	public static void setJcePolicy() {
//		try {
//			Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
//			field.setAccessible(true);
//			field.set(null, java.lang.Boolean.FALSE);
//		} catch (Exception ex) {
//			ex.printStackTrace();
//		}
//	}

	public static byte[] decrypt_data_symmetric(byte[] encData, Key k)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		byte[] iv = new byte[IV_SIZE];
		byte[] encryptedText;
		IvParameterSpec ivspec;

		byte[] encryptedIVAndText = Base64.getDecoder().decode(encData);
		int cipheredSize = encryptedIVAndText.length - IV_SIZE;
		encryptedText = new byte[cipheredSize];
		System.arraycopy(encryptedIVAndText, 0, iv, 0, IV_SIZE);
		ivspec = new IvParameterSpec(iv);

		System.arraycopy(encryptedIVAndText, IV_SIZE, encryptedText, 0, cipheredSize);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, k, ivspec);

		return cipher.doFinal(encryptedText);
	}

	public static byte[] decrypt_data_asymmetric(byte[] encData, Key k) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		byte[] aux = Base64.getDecoder().decode(encData);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, k);

		System.out.println("Base64 decoded: " + Base64.getDecoder().decode(encData).length);
		return cipher.doFinal(aux);
	}

	public static byte[] encrypt_data_symmetric(byte[] data, Key k) throws Exception {
		byte[] iv = new byte[IV_SIZE];
		IvParameterSpec ivspec;
		SecureRandom randomer = new SecureRandom();

		randomer.nextBytes(iv);
		ivspec = new IvParameterSpec(iv);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, k, ivspec);
		System.out.println("Base64 encoded: " + Base64.getEncoder().encode(data).length);
		byte[] ciphered = cipher.doFinal(data);
		byte[] encryptedIVAndText = new byte[IV_SIZE + ciphered.length];
		System.arraycopy(iv, 0, encryptedIVAndText, 0, IV_SIZE);
		System.arraycopy(ciphered, 0, encryptedIVAndText, IV_SIZE, ciphered.length);

		return Base64.getEncoder().encode(encryptedIVAndText);
	}

	public static byte[] encrypt_data_asymmetric(byte[] data, Key k) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, k);
		System.out.println("Base64 encoded: " + Base64.getEncoder().encode(data).length);

		return Base64.getEncoder().encode(cipher.doFinal(data));

	}

	public static byte[] sign_data(byte[] data, PrivateKey key)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		// generating a signature
		Signature dsaForSign = Signature.getInstance("SHA1withRSA");
		dsaForSign.initSign(key);
		dsaForSign.update(data);
		return Base64.getEncoder().encode(dsaForSign.sign());

	}

	public static boolean verifySignature(byte[] data, byte[] signature, PublicKey key)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		signature = Base64.getDecoder().decode(signature);
		Signature dsaForVerify = Signature.getInstance("SHA1withRSA");
		dsaForVerify.initVerify(key);
		dsaForVerify.update(data);
		return dsaForVerify.verify(signature);
		// System.out.println("Signature verifies: " + verifies);
	}

	private static byte[] hash_message(byte[] message) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		digest.update(message);
		byte[] hash = digest.digest();
		return Base64.getEncoder().encode(hash);
	}

	// may need to convert hex to string in hash_message
	private static String convertByteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++)
			stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16).substring(1));
		return stringBuffer.toString();
	}

	// getter for hash_message
	public static byte[] getHashMessage(byte[] message) throws NoSuchAlgorithmException {
		return hash_message(message);
	}

	// client should calculate the checksum of file it is sending,
	// send the checksum value with the request as param
	// server side: checksum should be compared against the checksum sent by the
	// client
	// if the two match file is good

	// integrity check for a file
	public static byte[] checkFileIntegrity(String filename) throws NoSuchAlgorithmException, IOException {
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		FileInputStream file = new FileInputStream(filename);
		byte[] dataBytes = new byte[1024];

		int toRead = 0;
		while ((toRead = file.read(dataBytes)) != -1) {
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

	// generate nonce
	public static byte[] generateNonce() {
		String dateTime = Long.toString(new Date().getTime());
		return dateTime.getBytes();
	}

}
