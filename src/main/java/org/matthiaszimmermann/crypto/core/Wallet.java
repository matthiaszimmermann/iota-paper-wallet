package org.matthiaszimmermann.crypto.core;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;

public abstract class Wallet {

	public static final String JSON_VERSION = "version";
	public static final String JSON_VERSION_VALUE = "1.0";
	public static final String JSON_ACCOUNT = "account";

	public static final String JSON_TECHNOLOGY = "technology";
	public static final String JSON_NETWORK = "network";

	public static final String DEFAULT_PATH_TO_DIRECTORY = System.getProperty("user.home");
	public static final String DEFAULT_FILE_EXTENSION = "json";

	private String pathToDirectory = DEFAULT_PATH_TO_DIRECTORY;
	private List<String> mnemonicWords = null;
	private String passPhrase = null;
	private Account account = null;

	protected Wallet(List<String> mnemonicWords, String passPhrase, Protocol protocol) {
		processProtocol(protocol);
		processPassPhrase(passPhrase);
		processMnemonicWords(mnemonicWords, protocol);
		restoreAccount(protocol);
	}
	
	// TODO remove parameter mnemonic words 
	public Wallet(File file, String passPhrase) throws Exception {
		processPassPhrase(passPhrase);
		restore(file);
	}

	/**
	 * Restores the wallet from the provided wallet file content and pass phrase
	 * @return 
	 */
	protected abstract Account restore(File file, String passPhrase) throws Exception;

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

	private void restoreAccount(Protocol protocol) {
		account = protocol.restoreAccount(mnemonicWords, passPhrase);
	}
	
	protected void restore(File file) throws Exception {

		if(file == null) { 
			throw new IllegalArgumentException("File parameter must not be null");
		}
		
		// check if provided file exists
		if(!file.exists() || file.isDirectory()) { 
			throw new IOException(String.format("File '%s' does not exist (or path is a directory)", file.getAbsolutePath()));
		}
		
		account = restore(file, passPhrase);
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
		return String.format("%s%s%s", getPathToDirectory(), File.separator, getFileName());
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
			obj.put(JSON_ACCOUNT, getAccount().toJson(getPassPhrase()));

			return obj;
		}
		catch(JSONException ex) {
			throw new RuntimeException(ex);
		}
	}

	/**
	 * Returns content of wallet as String.
	 * May be used to write wallet to a file system.
	 *
	 * @throws Exception 
	 */
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
