package org.matthiaszimmermann.crypto.iota;

import java.io.File;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

// TODO transfer creation /w offline signing
// http://ogrelab.ikratko.com/sending-new-transfer-to-iota-node-using-java-aka-sendtransfer/
public class Iota extends Protocol {
	
	public static final String TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	public Iota(Network network) {
		super(Technology.Iota, network);
	}
	
//	TODO remove/cleanup
//	@Override
//	public List<String> generateMnemonicWords() {
//		byte [] entropy = Entropy.generateEntropy();
//		List<String> wordList = null;
//
//		try {
//			wordList = Mnemonic.loadWordList();
//		} catch (IOException e) {
//			throw new RuntimeException("Failed to load mnemonic default word list");
//		}
//
//		return Mnemonic.toWords(entropy, wordList);
//	}

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
	public Wallet restoreWallet(File file, String passPhrase) {
		try {
			return new IotaWallet(file, passPhrase);
		} 
		catch (Exception e) {
			throw new RuntimeException("Failed to restore Iota wallet", e);
		} 	
	}

	@Override
	public Account createAccount(List<String> mnemonicWords, String passPhrase) {
		validateMnemonicWords(mnemonicWords);
		return new IotaAccount(mnemonicWords, passPhrase, getNetwork());
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
	
	// TODO move this to account. an account has to know how to derive the address from its secret
	// https://github.com/modum-io/tokenapp-keys-iota/blob/master/src/main/java/io/modum/IotaAddressGenerator.java
	public static String deriveAddressFromSeed(String seed) {
		ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
		int index = 0;

		try {			
			return IotaAPIUtils.newAddress(
					seed, 
					IotaAccount.SECURITY_LEVEL_DEFAULT,
					index, 
					IotaAccount.CHECKSUM_DEFAULT,
					curl);
		} 
		catch (ArgumentException e) {
			throw new IllegalArgumentException(e);
		}
	} 

}
