package org.matthiaszimmermann.crypto.iota;

import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

// TODO transfer creation /w offline signing
// http://ogrelab.ikratko.com/sending-new-transfer-to-iota-node-using-java-aka-sendtransfer/
public class Iota extends Protocol {
	
	public static final String TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	public Iota(Network network) {
		super(Technology.Iota, network);
	}

	@Override
	public void validateMnemonicWords(List<String> mnemonicWords) {
		if(mnemonicWords == null) {
			throw new IllegalArgumentException("Mnemonic words must not be null");
		}

		// TODO add some more validation here. if something looks bad throw an illegal arg exception	
	}
	
	@Override
	public Wallet createWallet(List<String> mnemonicWords, String passPhase) {
		validateMnemonicWords(mnemonicWords);
		return new IotaWallet(mnemonicWords, passPhase, getNetwork());
	}

	@Override
	public Wallet restoreWallet(JSONObject walletJson, String passPhrase) {
		try {
			return new IotaWallet(walletJson, passPhrase);
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to restore Ethereum wallet", e);
		} 	
	}

	@Override
	public Account createAccount(List<String> mnemonicWords, String passPhrase, Network network) {
		validateMnemonicWords(mnemonicWords);
		return new IotaAccount(mnemonicWords, passPhrase, network);
	}	

	@Override
	public Account restoreAccount(JSONObject accountJson, String passPhrase) {
		try {
			return new IotaAccount(accountJson, passPhrase, getNetwork());
		} 
		catch (JSONException e) {
			throw new RuntimeException("Failed to create Iota account from json object", e);
		}
	}
}
