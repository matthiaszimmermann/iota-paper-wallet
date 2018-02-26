package org.matthiaszimmermann.crypto.common;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.utility.AesUtility;

public abstract class Account {

	public static final String JSON_TECHNOLOGY = "technology";
	public static final String JSON_NETWORK = "network";

	public static final String JSON_ADDRESS = "address";
	public static final String JSON_SECRET = "secret";
	public static final String JSON_ENCRYPTED = "encrypted";
	public static final String JSON_IV = "iv";

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
	 * Convert account to JSONObject including private key/seed in plain text.
	 *
	 * @return JSONObject
	 */
	public JSONObject toJson() {
		return toJson(null);
	}
	
	/**
	 * Convert account to JSONObject including private key/seed in plain text.
	 *
	 * @return JSONObject
	 */
	public JSONObject toJson(String passPhrase) {
        JSONObject obj = new JSONObject();
        boolean encrypted = false;
        
		obj.put(JSON_TECHNOLOGY, getTechnology());
		obj.put(JSON_NETWORK, getNetwork());
        obj.put(JSON_ADDRESS, getAddress());
		
        if(passPhrase == null || passPhrase.length() == 0) {
            obj.put("secret", getSecret());
        }
        else {
			try {
				AesUtility aes = new AesUtility(passPhrase);
				encrypted = true;

				obj.put(JSON_SECRET, aes.encrypt(getSecret()));
				obj.put(JSON_IV, aes.getIv());
			}
			catch (Exception e) {
				new RuntimeException(e.getMessage());
			}
        }

        obj.put(JSON_ENCRYPTED, encrypted);
        
		return obj;
	}

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
	
	public Technology getTechnology() {
		return protocol == null ? null : protocol.getTechnology();
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
