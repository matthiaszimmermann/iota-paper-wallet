package org.matthiaszimmermann.crypto.core;

import java.io.File;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.utility.FileUtility;

public abstract class Wallet {

	public static final String JSON_VERSION = "version";
	public static final String JSON_VERSION_VALUE = "1.0";
	public static final String JSON_ACCOUNT = "account";

	public static final String JSON_TECHNOLOGY = "technology";
	public static final String JSON_NETWORK = "network";

	public static final String DEFAULT_PATH_TO_DIRECTORY = System.getProperty("user.home");
	public static final String DEFAULT_FILE_EXTENSION = "json";

	private String pathToDirectory = DEFAULT_PATH_TO_DIRECTORY;
	private String absolutePath = null;
	
	private List<String> mnemonicWords = null;
	private String passPhrase = null;
	protected Account account = null;

	protected Wallet(List<String> mnemonicWords, String passPhrase, Protocol protocol) {
		processProtocol(protocol);
		processPassPhrase(passPhrase);
		processMnemonicWords(mnemonicWords, protocol);
		
		account = protocol.createAccount(mnemonicWords, passPhrase);
	}

	public Wallet(File file, String passPhrase) throws Exception {
		processPassPhrase(passPhrase);

		JSONObject walletJson = readWalletFile(file);
		JSONObject accountJson = walletJson.getJSONObject(JSON_ACCOUNT);
		Protocol protocol = getProtocol(walletJson);

		absolutePath = file.getAbsolutePath();
		account = protocol.restoreAccount(accountJson, passPhrase);
	}

	private Protocol getProtocol(JSONObject walletJson) throws JSONException {
		Technology technology = Technology.get(walletJson.getString(JSON_TECHNOLOGY));
		Network network = Network.get(walletJson.getString(JSON_NETWORK));
		Protocol protocol = ProtocolFactory.getInstance(technology, network);
		return protocol;
	}

	protected void processProtocol(Protocol p) {
		if(p == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
	}

	protected void processMnemonicWords(List<String> mw, Protocol protocol) {
		if(mw == null || mw.size() == 0) {
			mnemonicWords = protocol.generateMnemonicWords();
		}
		else {
			mnemonicWords = mw;
		}

		protocol.validateMnemonicWords(mnemonicWords);
	}

	protected void processPassPhrase(String pp) {
		passPhrase = pp;
	}

	public List<String> getMnemonicWords() {
		return mnemonicWords;
	}

	public abstract String getSeed();

	public String getPassPhrase() {
		return passPhrase;
	}

	public Protocol getProtocol() {
		return account.getProtocol();
	}

	public Account getAccount() {
		return account;
	}

	public String getPathToDirectory() {
		return pathToDirectory;
	}

	public void setPathToDirectory(String pathToFile) {
		this.pathToDirectory = pathToFile;
	}

	public String getAbsolutePath() {
		return absolutePath != null ? absolutePath : String.format("%s%s%s", getPathToDirectory(), File.separator, getFileName());
	}

	public String getFileName() {
		String ext = getFileExtension();
		return ext == null || ext.length() == 0 ? 
				getFileBaseName() : String.format("%s.%s", getFileBaseName(), ext);
	}

	/**
	 * Returns the wallet file base name without path to file and without extension.
	 */
	public String getFileBaseName() {
		if(getAccount() == null) {
			return null;
		}

		return getAccount().getAddress();
	}

	/** 
	 * Returns the wallet file extension.
	 */
	public String getFileExtension() {
		return DEFAULT_FILE_EXTENSION;
	}

	/**
	 * Returns wallet as JSONObject.
	 * 
	 * @throws Exception 
	 */
	public JSONObject toJson() {
		try {
			JSONObject obj = new JSONObject();

			obj.put(JSON_VERSION, JSON_VERSION_VALUE);

			Protocol p = getProtocol();
			if(p != null) {
				obj.put(JSON_TECHNOLOGY, p.getTechnology());
				obj.put(JSON_NETWORK, p.getNetwork());
			}

			boolean includeProtocolInfo = false;
			obj.put(JSON_ACCOUNT, getAccount().toJson(getPassPhrase(), includeProtocolInfo));

			return obj;
		}
		catch(JSONException ex) {
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Reads the file into a JSON object and performs some basic checks.
	 * Checks include test for version, technology, network and account.
	 * @param file the file to read/verify
	 * @return the file content as JSON object
	 * @throws JSONException
	 */
	protected JSONObject readWalletFile(File file) throws JSONException {
		String jsonString = FileUtility.readTextFile(file);

		if(jsonString.isEmpty()) {
			throw new JSONException("Empty wallet file");
		}

		// convert wallet file string to json object
		JSONObject node = new JSONObject(jsonString);

		// check and extract version
		if(!node.has(JSON_VERSION)) {
			throw new JSONException("Wallet file has no version attribute");
		}

		if(!JSON_VERSION_VALUE.equals(node.getString(JSON_VERSION))) {
			throw new JSONException("Wallet file has unkonwn version. Expected value: " + JSON_VERSION_VALUE);
		}

		// check and extract protocol
		if(!node.has(JSON_TECHNOLOGY)) {
			throw new JSONException("Wallet file has no technology attribute");
		}

		if(!node.has(JSON_NETWORK)) {
			throw new JSONException("Wallet file has no network attribute");
		}

		if(!node.has(JSON_ACCOUNT)) {
			throw new JSONException("Wallet file has no account attribute");
		}

		return node;
	}

	/**
	 * Returns content of wallet as String.
	 * May be used to write wallet to a file system.
	 */
	@Override
	public String toString() {
		return toJson().toString().replace(",\"", ", \"");
	}

	@Override
	public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		}

		if(!(obj instanceof Wallet)) {
			return false;
		}

		Wallet other = (Wallet)obj;

		if(mnemonicWords != null && !mnemonicWords.equals(other.mnemonicWords)) {
			return false;
		} 

		if(passPhrase != null && !passPhrase.equals(other.passPhrase)) {
			return false;
		}

		return account.equals(other.account);
	}

	@Override
	public int hashCode() {
		int mHash = mnemonicWords == null ? 0 : Mnemonic.convert(mnemonicWords).hashCode();
		int pHash = passPhrase == null ? 0 : passPhrase.hashCode();
		int aHash = account == null ? 0 : account.hashCode();

		return mHash | pHash | aHash;
	}
}
