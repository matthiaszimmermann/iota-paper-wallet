package org.matthiaszimmermann.crypto.bitcoin;

import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class BitcoinWallet extends Wallet {
	
	public static final String SECRET_LABEL = "Mnemonic Seed";

	public BitcoinWallet(JSONObject walletJson, String passPhrase) throws JSONException {
		super(walletJson, passPhrase);
	}

	public BitcoinWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		super(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Bitcoin, network));
	}

	@Override
	public String getSecretLabel() {
		return SECRET_LABEL;
	}
}
