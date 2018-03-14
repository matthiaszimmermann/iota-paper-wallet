package org.matthiaszimmermann.crypto.bitcoin;

import java.io.File;
import java.util.List;

import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;

public class BitcoinWallet extends Wallet {

	public BitcoinWallet(File file, String passPhrase) throws Exception {
		super(file, passPhrase);
	}

	public BitcoinWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		this(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Bitcoin, network));
	}

	protected BitcoinWallet(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		super(mnemonicWords, passPhase, protocol);
		account = new BitcoinAccount(mnemonicWords, getPassPhrase(), protocol.getNetwork());		
	}

	@Override
	public String getSeed() {
		return getAccount().getSecret();
	}
}
