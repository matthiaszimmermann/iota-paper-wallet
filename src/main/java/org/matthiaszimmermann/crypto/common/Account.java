package org.matthiaszimmermann.crypto.common;

import org.json.JSONObject;

public abstract class Account {

	private String secret;
	private String address;
	private Protocol protocol;
	
	protected Account() { }
	
	public Account(Protocol protocol) { 
		processProtocol(protocol);
	}
	
	public Account(String secret, String address, Protocol protocol) {
		processSecret(secret);		
		processAddress(address);
		processProtocol(protocol);
	}
	
	/**
	 * Write address to JSONObject.
	 * For debugging only.
	 *
	 * @return JSONObject
	 *
	 */
	public abstract JSONObject toJson();

	private void processAddress(String address) {
		if(address == null) {
			throw new IllegalArgumentException("Address must not be null");
		}
		
		this.address = address;
	}
	
	private void processSecret(String secret) {
		if(secret == null) {
			throw new IllegalArgumentException("Secret must not be null");
		}
		
		this.secret = secret;
	}

	private void processProtocol(Protocol protocol) {
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
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
	
	public Network getNetwork() {
		return protocol == null ? null : protocol.getNetwork();
	}	
	
	@Override
	public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		}
		
		if(!(obj instanceof Account)) {
			return false;
		}
		
		Account other = (Account)obj;
		
		return secret.equals(other.secret) 
				&& address.equals(other.address) 
				&& protocol.equals(other.protocol);
	}
	
	@Override
	public int hashCode() {
		return secret.hashCode() | address.hashCode() | protocol.hashCode();
	}
}
