package org.matthiaszimmermann.crypto.ethereum;

import java.io.File;
import java.util.List;

import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class EthereumWallet extends Wallet {

	public EthereumWallet(File file, String passPhrase) throws Exception {
		super(file, passPhrase);
	}

	public EthereumWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		this(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Ethereum, network));
	}

	protected EthereumWallet(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		super(mnemonicWords, passPhase, protocol);
	}

	@Override
	public String getSeed() {
		return getAccount().getSecret();
	}
}
