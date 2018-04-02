package org.matthiaszimmermann.crypto.iota;

import java.util.List;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class IotaWallet extends Wallet {
	
	public static final String SECRET_LABEL = "Seed";

	public IotaWallet(JSONObject walletJson, String passPhrase) throws Exception {
		super(walletJson, passPhrase);
	}

	public IotaWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		super(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Iota, network));
	}

	@Override
	public String getSecretLabel() {
		return SECRET_LABEL;
	}
}
