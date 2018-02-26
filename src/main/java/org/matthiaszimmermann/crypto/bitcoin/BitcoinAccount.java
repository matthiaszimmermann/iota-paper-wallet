package org.matthiaszimmermann.crypto.bitcoin;

import java.util.ArrayList;
import java.util.List;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.Network;

/**
 *
 * BitcoinAccount.java : an address in a BIP44 wallet account chain
 *
 */
public class BitcoinAccount extends Account {

	private List<String> bip39seed;
	private DeterministicKey dk;
	
	private List<Chain> chains = null;
	
	public BitcoinAccount(String secret, String address, Network network) {
		super(secret, address, new Bitcoin(network));
	}


	/**
	 * Constructor for account.
	 *
	 * @param List<String> mnemonicWords the BIP39 seed word list for this HD account
	 * @param NetworkParameters params
	 */
	public BitcoinAccount(List<String> mnemonicWords, Network network) {
		super(new Bitcoin(network));
		
		bip39seed = mnemonicWords;
		
		byte [] seed = MnemonicCode.toSeed(bip39seed, "");		
		DeterministicKey rootKey = ((Bitcoin)getProtocol()).seedToRootKey(seed);
		int child = rootKey.getChildNumber().num();
		int childnum = child | ChildNumber.HARDENED_BIT;
        dk = HDKeyDerivation.deriveChildKey(rootKey, childnum);
        
        chains = new ArrayList<>();
        chains.add(new Chain(dk, true, network));
        chains.add(new Chain(dk, false, network));
	}
	
	@Override
	public String getAddress() {
		Chain chain = getReceive();
		Address address = chain.getAddressAt(0);
		return address.getAddressString();
	}

	/**
	 * Return private key for this address (compressed WIF format).
	 *
	 * @return String
	 *
	 */
	@Override
	public String getSecret() {
		return String.join(" ", bip39seed);
	}
	
	
    /**
     * Return receive chain this account.
     *
     * @return HD_Chain
     *
     */
    private Chain getReceive() {
        return chains.get(0);
    }

	/**
	 * Return BIP44 path for this address (m / purpose' / coin_type' / account' / chain / address_index).
	 *
	 * @return String
	 *
	 */
    // TODO decide if method should be removed (what's the value of having access to path info?)
	protected String getPath() {
		return dk == null ? null : dk.getPathAsString();
	}

	@Override
	public JSONObject toJson(String passPhrase) {
        try {
            JSONObject obj = super.toJson(passPhrase);
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
