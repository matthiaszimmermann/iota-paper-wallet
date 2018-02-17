package org.matthiaszimmermann.crypto.bitcoin;

import java.util.ArrayList;
import java.util.List;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
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

	private DeterministicKey dk;
//	private ECKey ecKey = null;
	
	private List<Chain> chains = null;
	
	// TODO cleanup commented stuff
//	private byte[] pubKey = null;
//	private byte[] pubKeyHash = null;
//
//	private DeterministicKey aKey = null;
//	private int	aID;
//
//	private String strXPUB = null;

	public BitcoinAccount(String secret, String address, Network network) {
		super(secret, address, new Bitcoin(network));
	}

	/**
	 * Constructor for account.
	 *
	 * @param DeterministicKey rootKey deterministic key for this account
	 * @param int child id within the wallet for this account
	 * @param NetworkParameters params
	 */
	public BitcoinAccount(DeterministicKey rootKey, int child, Network network) {
		super(new Bitcoin(network));

		int childnum = child | ChildNumber.HARDENED_BIT;
        dk = HDKeyDerivation.deriveChildKey(rootKey, childnum);
        
        chains = new ArrayList<>();
        chains.add(new Chain(dk, true, network));
        chains.add(new Chain(dk, false, network));
	}
	
//
//	/**
//	 * Get pubKey as byte array.
//	 *
//	 * @return byte[]
//	 *
//	 */
//	public byte[] getPubKey() {
//		return pubKey;
//	}
//
//	/**
//	 * Get pubKeyHash as byte array.
//	 *
//	 * @return byte[]
//	 *
//	 */
//	public byte[] getPubKeyHash() {
//		return pubKeyHash;
//	}

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
		// TODO implement or remove
		return null;
	}
	
	
    /**
     * Return receive chain this account.
     *
     * @return HD_Chain
     *
     */
    public Chain getReceive() {
        return chains.get(0);
    }

	/**
	 * Return BIP44 path for this address (m / purpose' / coin_type' / account' / chain / address_index).
	 *
	 * @return String
	 *
	 */
	protected String getPath() {
		return dk == null ? null : dk.getPathAsString();
	}

	/**
	 * Write address to JSONObject.
	 * For debugging only.
	 *
	 * @return JSONObject
	 *
	 */
	public JSONObject toJson() {
		return toJson(false);
	}

	private JSONObject toJson(boolean includeKey) {
        try {
            JSONObject obj = new JSONObject();

            // TODO cleanup
            // add keys
//            if(aKey.hasPrivKey() && includeKey) {
//                obj.put("path", getPath());
//                obj.put("xpub", xpubstr());
//                obj.put("xprv", xprvstr());
//            }

            // add chains
            JSONArray chainsArray = new JSONArray();
            for(Chain chain : chains)   {
                chainsArray.put(chain.toJSON());
            }
            
            obj.put("chains", chainsArray);

            return obj;
        }
        catch(JSONException ex) {
            throw new RuntimeException(ex);
        }
    }
}
