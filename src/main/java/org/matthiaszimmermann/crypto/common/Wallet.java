package org.matthiaszimmermann.crypto.common;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.json.JSONObject;

public abstract class Wallet {

	public static final String DEFAULT_PATH_TO_DIRECTORY = System.getProperty("user.home");
	public static final String DEFAULT_FILE_EXTENSION = "json";

	private List<String> mnemonicWords = null;
	private String passPhrase = null;
	
	// TODO get rid of this member as this is already contained in account member
	// private Protocol protocol = null;

	private Account account = null;
	private String pathToDirectory = DEFAULT_PATH_TO_DIRECTORY;

	protected Wallet(List<String> mnemonicWords, String passPhrase, Protocol protocol) {
		processProtocol(protocol);
		processPassPhrase(passPhrase);
		processMnemonicWords(mnemonicWords, protocol);
		restoreAccount(protocol);
	}
	
	public Wallet(File file, List<String> mnemonicWords, String passPhrase) throws Exception {
		processPassPhrase(passPhrase);
		restoreAccount(file);
	}

	protected void processProtocol(Protocol p) {
		if(p == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}

		// TODO cleanup
		// protocol = p;
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
	
	protected void restoreAccount(File file) throws Exception {
		
		// check if provided file exists
		if(!file.exists() || file.isDirectory()) { 
			throw new IOException(String.format("File '%s' does not exist (or path is a directory)", file.getAbsolutePath()));
		}
		
		account = restoreAccount(FileUtility.readTextFile(file), mnemonicWords, passPhrase);
	}

	/**
	 * Restores the wallet from the provided wallet file content and pass phrase
	 * @return 
	 */
	protected abstract Account restoreAccount(String fileContent, List<String> mnemonicWords, String passPhrase) throws Exception;

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
	public abstract JSONObject toJson();

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
