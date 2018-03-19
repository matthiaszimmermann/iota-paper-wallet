package org.matthiaszimmermann.crypto.core;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.utility.AesUtility;

public abstract class Account {

	public static final String JSON_TECHNOLOGY = "technology";
	public static final String JSON_NETWORK = "network";

	public static final String JSON_ADDRESS = "address";
	public static final String JSON_SECRET = "secret";
	public static final String JSON_ENCRYPTED = "encrypted";
	public static final String JSON_IV = "iv";

	protected String address;
	protected String secret;
	protected String passPhrase;
	protected Protocol protocol;

	public Account(String passPhrase, Protocol protocol) {
		processPassPhrase(passPhrase);
		processProtocol(protocol);
	}

	public Account(JSONObject node, String passPhrase, Protocol protocol) throws JSONException {
		processPassPhrase(passPhrase);
		processAddress(node);
		processSecret(node);
		processProtocol(protocol);
	}

	/**
	 * Sets pass phrase member variable and converts a null value into an empty string.
	 */
	private void processPassPhrase(String passPhrase) {
		this.passPhrase = passPhrase == null ? "" : passPhrase;
	}

	/**
	 * Extracts address member variable from provided node.
	 */
	private void processAddress(JSONObject node) throws JSONException {
		if(!node.has(JSON_ADDRESS)) {
			throw new JSONException("Account node has no address attribute");
		}

		address = node.getString(JSON_ADDRESS);
	}

	/**
	 * Extracts address member variable from provided node.
	 */
	private void processSecret(JSONObject node) throws JSONException {
		// check and extract seed
		if(!node.has(JSON_SECRET)) {
			throw new JSONException("Account node has no secret attribute");
		}

		if(!node.has(JSON_ENCRYPTED)) {
			throw new JSONException("Account node has no encrypted attribute");
		}

		// get secret
		if(node.getBoolean(JSON_ENCRYPTED)) {
			if(passPhrase.length() == 0) {
				throw new JSONException("No password provided for encrypted account json");
			}
			
			if(!node.has(JSON_IV)) {
				throw new JSONException("Wallet file has no IV attribute (required for encrypted seed)");
			}

			try {
				AesUtility aes = new AesUtility(passPhrase);
				String iv = node.getString(JSON_IV);
				String seedEncrypted = node.getString(JSON_SECRET);

				secret = aes.decrypt(seedEncrypted, iv);
			} 
			catch (Exception e) {
				throw new RuntimeException("Failed to decrypt account secret", e);
			}
		}
		else {
			secret = node.getString(JSON_SECRET);
		}
	}

	private void processProtocol(Protocol protocol) {
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}

		this.protocol = protocol;
	}

	/**
	 * Returns content of account as String.
	 * May be used to write account to a file system.
	 */
	@Override
	public String toString() {
		return toJson().toString().replace(",\"", ", \"");
	}

	/**
	 * Convert account to JSONObject including private key/seed in plain text.
	 *
	 * @return JSONObject
	 * @throws JSONException 
	 */
	public JSONObject toJson() {
		try {
			return toJson(true);
		}
		catch(JSONException ex) {
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Convert account to JSONObject including private key/seed.
	 * @param includeProtocolInfo adds protocol attributes iff true
	 * @return JSON representation of this account
	 * @throws JSONException 
	 */
	public JSONObject toJson(boolean includeProtocolInfo) throws JSONException {
		JSONObject obj = new JSONObject();
		boolean encrypted = false;

		obj.put(JSON_ADDRESS, getAddress());

		if(includeProtocolInfo) {
			obj.put(JSON_TECHNOLOGY, getTechnology());
			obj.put(JSON_NETWORK, getNetwork());
		}

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

		return getSecret().equals(other.getSecret()) 
				&& getAddress().equals(other.getAddress()) 
				&& getProtocol().equals(other.getProtocol());
	}

	@Override
	public int hashCode() {
		return getSecret().hashCode() | getAddress().hashCode() | getProtocol().hashCode();
	}
}
