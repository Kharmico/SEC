package Crypto;

import java.io.Serializable;
import java.security.PublicKey;

public class Message  implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private PublicKey pubKey;
	private byte[] domain;
	private byte[] username;
	private String deviceId;
	private byte[] password;
	private byte[] nonce;
	private byte[] passwordSignature;
	private long timeStamp;
	
	private void init(PublicKey pubKey,byte[] nonce,String deviceId){
		this.pubKey=pubKey;
		this.deviceId=deviceId;
		this.nonce=nonce;
	}
	
	public Message(){
		
	}

	public Message(PublicKey pubKey,byte[] domain, byte[] username,byte[] password, byte[] nonce,String deviceId, long timeStamp){
		this.init(pubKey,nonce, deviceId);
		this.domain=domain;
		this.username=username;
		this.password=password;
		this.timeStamp = timeStamp;
	}
		
	
	public Message(PublicKey pubKey, byte[] nonce,String deviceId){
		this.init(pubKey,nonce, deviceId);	
		
	}
	public Message(PublicKey pubKey, byte[] domain, byte[] username, byte[] nonce, String deviceId, long timeStamp) {
		this.init(pubKey,nonce, deviceId);	
		this.domain=domain;
		this.username=username;
		this.timeStamp = timeStamp;
	}

	public PublicKey getPubKey(){
		return this.pubKey;
	}
	public byte[] getDomain() {
		return domain;
	}
	public byte[] getUsername() {
		return username;
	}
	public byte[] getPassword() {
		return password;
	}
	
	public byte[] getNounce() {
		return nonce;
	}
	public String getDeviceId() {
		return deviceId;
	}

	public void setPassword(byte[] password,byte[] passwordSignature) {
		this.password=password;
		this.passwordSignature=passwordSignature;
	}
	public byte[] getPasswordSignature(){
		return this.passwordSignature;
	}
	
}
