package org.matthiaszimmermann.crypto.bitcoin;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;

/**
 *
 * BitcoinAccount.java : an address in a BIP44 wallet account chain
 *
 */
public class BitcoinAccount extends Account {

	private List<Chain> chains = null;

	/**
	 * Constructor for account.
	 *
	 * @param List<String> mnemonicWords the BIP39 seed word list for this HD account
	 * @param NetworkParameters params
	 */
	public BitcoinAccount(List<String> mnemonicWords, String passPhrase, Network network) {
		super(mnemonicWords, passPhrase, new Bitcoin(network));

		chains = getChains(mnemonicWords, getNetwork());
	}

	public BitcoinAccount(JSONObject accountJson, String passPhrase, Network network) throws JSONException {
		super(accountJson, passPhrase, new Bitcoin(network));
		
		List<String> mnemonicWords = new ArrayList<String>(Arrays.asList(getSecret().split(" ")));
		chains = getChains(mnemonicWords, getNetwork());
	}

	@Override
	public String deriveSecret(List<String> menmonicWords, String passPhrase) {
		return String.join(" ", menmonicWords);
	}

	@Override
	public String deriveAddress(String secret, Network network) {
		List<String> mnemonicWords = new ArrayList<String>(Arrays.asList(secret.split(" ")));
		DeterministicKey dk = getDeterministicKey(mnemonicWords);
		Chain receiveChain = new Chain(dk, true, network);
		Address address = receiveChain.getAddressAt(0);
		
		return address.getAddressString();
	}

	@Override
	public JSONObject toJson(boolean includePrototolInfo) {
		try {
			JSONObject obj = super.toJson(includePrototolInfo);
			obj.put("chains", chainsToJson());
			return obj;
		}
		catch(JSONException ex) {
			throw new RuntimeException(ex);
		}
	}

	private List<Chain> getChains(List<String> mnemonicWords, Network network) {
		DeterministicKey dk = getDeterministicKey(mnemonicWords);
		List<Chain> chains = new ArrayList<>();
		chains.add(new Chain(dk, true, network)); // receive chain
		chains.add(new Chain(dk, false, network)); // change chain
		
		return chains;
	}

	private DeterministicKey getDeterministicKey(List<String> mnemonicWords) {
		// the passPhrase needs to be set to an empty string, otherwise the resulting addresses do not match 
		// those produced by the electrum wallet
		byte [] seed = MnemonicCode.toSeed(mnemonicWords, "");
		
		DeterministicKey rootKey = ((Bitcoin)getProtocol()).seedToRootKey(seed);
		int child = rootKey.getChildNumber().num();
		int childnum = child | ChildNumber.HARDENED_BIT;
		
		return HDKeyDerivation.deriveChildKey(rootKey, childnum);
	}

	private JSONArray chainsToJson() {
		JSONArray chainsArray = new JSONArray();
		for(Chain chain : chains)   {
			chainsArray.put(chain.toJSON());
		}
		return chainsArray;
	}
}
