package org.matthiaszimmermann.crypto.bitcoin;

import java.io.File;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;
import org.matthiaszimmermann.crypto.utility.AesUtility;
import org.matthiaszimmermann.crypto.utility.FileUtility;

public class BitcoinWallet extends Wallet {

	// TODO cleanup constants
	public static final String JSON_SEED = "seed";
	public static final String JSON_IV = "iv";
	public static final String JSON_ENCRYPTED = "encrypted";
	public static final String JSON_ADDRESS = "address";

	private BitcoinAccount account = null;

	public BitcoinWallet(File file, String passPhrase) throws Exception {
		super(file, passPhrase);
	}

	public BitcoinWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		this(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Bitcoin, network));
	}

	protected BitcoinWallet(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		super(mnemonicWords, passPhase, protocol);
		account = new BitcoinAccount(mnemonicWords, protocol.getNetwork());		
	}

	@Override
	public String getSeed() {
		return getAccount().getSecret();
	}

	@Override
	public Account getAccount() {
		return account;
	}

	// TODO decide if this should be called restoreAccount. and if so if method should be moved to bitcoin account class
	@Override
	protected Account restore(File file, String passPhrase) throws Exception {
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

		if(!Technology.Bitcoin.name().equals(node.getString(JSON_TECHNOLOGY))) {
			throw new JSONException("Wallet file has unexpected technology attribute. Expected value: " + Technology.Bitcoin);
		}

		if(!node.has(JSON_NETWORK)) {
			throw new JSONException("Wallet file has no network attribute");
		}

		if(!node.has(JSON_ENCRYPTED)) {
			throw new JSONException("Wallet file has no encrypted attribute");
		}

		if(!node.has(JSON_SEED)) {
			throw new JSONException("Wallet file has no seed attribute");
		}

		if(!node.has(JSON_ACCOUNT)) {
			throw new JSONException("Wallet file has no account attribute");
		}

		@SuppressWarnings("unused")
		String seed = null;

		// get mnemonic and seed
		if(node.getBoolean(JSON_ENCRYPTED)) {
			if(!node.has(JSON_IV)) {
				throw new JSONException("Wallet file has no iv attribute (required for encrypted seed)");
			}

			AesUtility aes = new AesUtility(passPhrase);
			String iv = node.getString(JSON_IV);
			String seedEncrypted = node.getString(JSON_SEED);

			seed = aes.decrypt(seedEncrypted, iv);
		}
		else {
			seed = node.getString(JSON_SEED);
		}

		// TODO add checks to verify that account matches seed 
		// account = new BitcoinAccount(node.getJSONObject(JSON_ACCOUNT));

		return account;
	}
}
