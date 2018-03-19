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
		super(passPhrase, new Bitcoin(network));

		getProtocol().validateMnemonicWords(mnemonicWords);
		DeterministicKey dk = getDeterministicKey(mnemonicWords);
		
		secret = String.join(" ", mnemonicWords);
		chains = getChains(dk, network);
	}

	public BitcoinAccount(JSONObject accountJson, String passPhrase, Network network) throws JSONException {
		super(accountJson, passPhrase, new Bitcoin(network));
		
		List<String> mnemonicWords = new ArrayList<String>(Arrays.asList(secret.split(" ")));
		DeterministicKey dk = getDeterministicKey(mnemonicWords);
		
		chains = getChains(dk, network);		
	}

	private DeterministicKey getDeterministicKey(List<String> mnemonicWords) {
		byte [] seed = MnemonicCode.toSeed(mnemonicWords, passPhrase);
		
		DeterministicKey rootKey = ((Bitcoin)getProtocol()).seedToRootKey(seed);
		int child = rootKey.getChildNumber().num();
		int childnum = child | ChildNumber.HARDENED_BIT;
		
		return HDKeyDerivation.deriveChildKey(rootKey, childnum);
	}

	private List<Chain> getChains(DeterministicKey dk, Network network) {
		List<Chain> chains = new ArrayList<>();
		chains.add(new Chain(dk, true, network));
		chains.add(new Chain(dk, false, network));
		
		return chains;
	}

	@Override
	public String getAddress() {
		Chain chain = getReceive();
		Address address = chain.getAddressAt(0);
		return address.getAddressString();
	}

	/**
	 * Return receive chain this account.
	 *
	 * @return HD_Chain
	 *
	 */
	protected Chain getReceive() {
		return chains.get(0);
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

	private JSONArray chainsToJson() {
		JSONArray chainsArray = new JSONArray();
		for(Chain chain : chains)   {
			chainsArray.put(chain.toJSON());
		}
		return chainsArray;
	}
}
