package Crypto;

import java.io.Serializable;
import java.security.PublicKey;

public class Message implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
//	private PublicKey senderPubKey;
	private PublicKey clientPubKey;
	private byte[] domain;
	private byte[] username;
	private String deviceId;
	private Password password;
	private byte[] nounce;
	private long timeStamp;
	private int status;
	private String url;

	private void init(PublicKey clientPubKey, byte[] nounce, String deviceId) {
		this.clientPubKey = clientPubKey;
		this.deviceId = deviceId;
		this.nounce = nounce;
	}

	public Message() {

	}

	public Message(PublicKey clientPubKey, byte[] domain, byte[] username, Password password,
			byte[] nonce, String deviceId, long timeStamp) {
		this.init(clientPubKey, nonce, deviceId);
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.timeStamp = timeStamp;
	}

	public Message(PublicKey senderPubKey, PublicKey clientPubKey, byte[] domain, byte[] username, Password password,
			byte[] nonce, String deviceId, long timeStamp, int status) {
		this.init(senderPubKey, nonce, deviceId);
		this.domain = domain;
		this.username = username;
		this.password = password;
		this.timeStamp = timeStamp;
		this.status = status;
	}

	public Message(PublicKey clientPublicKey, byte[] nonce, String deviceId) {
		this.init(clientPublicKey, nonce, deviceId);

	}

	public Message(PublicKey clientPublicKey, byte[] domain, byte[] username, byte[] nonce, String deviceId,
			long timeStamp) {
		this.init(clientPublicKey, nonce, deviceId);
		this.domain = domain;
		this.username = username;
		this.timeStamp = timeStamp;
	}

	public Message( PublicKey clientPublicKey, byte[] domain, byte[] username, Password password,
			byte[] nonce, String deviceId) {
		this.init(clientPublicKey, nonce, deviceId);
		this.domain = domain;
		this.username = username;
		this.password = password;
		
	}

	public byte[] getDomain() {
		return domain;
	}

	public byte[] getUsername() {
		return username;
	}

	public Password getPassword() {
		return password;
	}

	public byte[] getNounce() {
		return nounce;
	}

	public String getDeviceId() {
		return deviceId;
	}

	public long getTimeStamp() {
		return timeStamp;
	}

	public void setPassword(Password password) {
		this.password = password;

	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public void setNounce(byte[] nonce) {
		this.nounce = nonce;
	}

	public PublicKey getClientPubKey() {
		return clientPubKey;
	}

	public void setClientPubKey(PublicKey clientPubKey) {
		this.clientPubKey = clientPubKey;
	}
	public void setUrl(String url){
		this.url=url;
	}
	public String getUrl(){
		return this.url;
	}
}
