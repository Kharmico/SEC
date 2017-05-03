package Crypto;

import java.io.Serializable;

public class Password implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private byte[] domain;
	private byte[] username;
	private byte[] password;
	private byte[] pduSignature;
	private long timeStamp;
	private String deviceId;
	
	public Password() {
	}

	public Password(byte[] domain, byte[] username, byte[] password, byte[] pduSignature, long timeStamp) {
		this.domain=domain;
		this.username=username;
		this.password=password;
		this.pduSignature=pduSignature;
		this.timeStamp = timeStamp;
	}
	public Password(byte[] domain, byte[] username, byte[] password, byte[] pduSignature) {
		this.domain=domain;
		this.username=username;
		this.password=password;
		this.pduSignature=pduSignature;
		this.timeStamp = 0;
	}

	public byte[] getDomain() {
		return domain;
	}
	
	public String getDeviceId(){
		return deviceId;
	}
	public void setDomain(byte[] domain) {
		this.domain = domain;
	}

	public byte[] getUsername() {
		return username;
	}

	public void setUsername(byte[] username) {
		this.username = username;
	}

	public byte[] getPassword() {
		return password;
	}

	public void setPassword(byte[] password) {
		this.password = password;
	}

	public byte[] getPasswordSignature() {
		return pduSignature;
	}

	public void setPasswordSignature(byte[] passwordSignature) {
		this.pduSignature = passwordSignature;
	}
	
	public long getTimeStamp() {
		return this.timeStamp;
	}
	
	public void setTimeStamp(long timeStamp){
		this.timeStamp = timeStamp;
	}
	
	@Override
	public boolean equals(Object obj){
		if (obj == null) return false;
		if (obj == this) return true;		
		
		if(obj instanceof Password) {
			Password objAux = (Password) obj;
			if(objAux.getDomain().equals(this.domain) && objAux.getPassword().equals(this.password) && 
					objAux.getUsername().equals(this.username) && objAux.getPasswordSignature().equals(this.pduSignature))
				return true;
			else return false;
		}
		return false;
	}
	
}
