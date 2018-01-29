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
	private Protocol protocol = null;

	private Account account = null;
	private String pathToDirectory = DEFAULT_PATH_TO_DIRECTORY;

	protected Wallet(List<String> mnemonicWords, String passPhrase, Protocol protocol) {
		processProtocol(protocol);
		processMnemonicWords(mnemonicWords);
		processPassPhrase(passPhrase);
		restoreAccount();
	}
	
	public Wallet(File file, String passPhrase) throws Exception {
		processPassPhrase(passPhrase);
		restoreWallet(file);
	}

	protected void processProtocol(Protocol p) {
		if(p == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}

		protocol = p;
	}

	protected void processMnemonicWords(List<String> mw) {
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

	private void restoreAccount() {
		account = protocol.restoreAccount(mnemonicWords, passPhrase);
	}
	
	protected void restoreWallet(File file) throws Exception {
		
		// check if provided file exists
		if(!file.exists() || file.isDirectory()) { 
			throw new IOException(String.format("File '%s' does not exist (or path is a directory)", file.getAbsolutePath()));
		}
		
		restoreWallet(FileUtility.readTextFile(file), passPhrase);
	}

	/**
	 * Restores the wallet from the provided wallet file content and pass phrase
	 */
	protected abstract void restoreWallet(String fileContent, String passPhrase) throws Exception;

	public List<String> getMnemonicWords() {
		return mnemonicWords;
	}

	public String getPassPhrase() {
		return passPhrase;
	}

	public Protocol getProtocol() {
		return protocol;
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
		return toJson().toString();
	}
	
	// TODO implement default equals method (and use it for wallet file verification)
}
