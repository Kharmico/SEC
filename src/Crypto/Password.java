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

	public Password() {
	}

	public Password(byte[] domain, byte[] username, byte[] password, byte[] pduSignature) {
		this.domain=domain;
		this.username=username;
		this.password=password;
		this.pduSignature=pduSignature;

	}

	public byte[] getDomain() {
		return domain;
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

	
}
