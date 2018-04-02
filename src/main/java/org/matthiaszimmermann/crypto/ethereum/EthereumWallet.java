package org.matthiaszimmermann.crypto.ethereum;

import java.util.List;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class EthereumWallet extends Wallet {
	
	public static final String SECRET_LABEL = "Private Key";

	public EthereumWallet(JSONObject walletJson, String passPhrase) throws Exception {
		super(walletJson, passPhrase);
	}

	public EthereumWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		super(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Ethereum, network));
	}

	@Override
	public String getSecretLabel() {
		return SECRET_LABEL;
	}
}
