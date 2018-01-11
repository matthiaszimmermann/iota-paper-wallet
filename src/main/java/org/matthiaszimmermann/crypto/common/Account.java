package org.matthiaszimmermann.crypto.common;

public abstract class Account {

	private String secret;
	private String address;
	private Protocol protocol;
	
	protected Account(String secret, String address, Protocol protocol) {
		
		if(secret == null) {
			throw new IllegalArgumentException("Secret must not be null");
		}
		
		if(address == null) {
			throw new IllegalArgumentException("Address must not be null");
		}
		
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
		this.secret = secret;
		this.address = address;
		this.protocol = protocol;
	}
	
	public String getAddress() {
		return address;
	}
	
	public String getSecret() {
		return secret;
	}

	public Protocol getProtocol() {
		return protocol;
	}
}
