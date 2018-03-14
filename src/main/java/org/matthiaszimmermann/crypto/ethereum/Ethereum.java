package org.matthiaszimmermann.crypto.ethereum;

import java.util.List;

import org.bitcoinj.crypto.MnemonicCode;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Entropy;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;

public class Ethereum extends Protocol {

	public static final int MNEMONIC_LENGTH_MIN = 12;
	public static final int MNEMONIC_LENGTH_MAX = 24;

	public Ethereum(Network network) {
		super(Technology.Ethereum, network);
	}

	@Override
	public Account createAccount(List<String> mnemonicWords, String passPhrase) {
		return new EthereumAccount(mnemonicWords, passPhrase, getNetwork());
	}

	@Override
	public Account restoreAccount(JSONObject accountJson, String passPhrase) {
		return new EthereumAccount(accountJson, passPhrase, getNetwork());
	}

	// TODO check if this fits ethereum (as the code below is copy paste from bitcoin)
	@Override
	public List<String> generateMnemonicWords() {
		byte [] entropy = Entropy.generateEntropy();
		
		try {
			MnemonicCode mc = new MnemonicCode();
			return mc.toMnemonic(entropy);
		} 
		catch (Exception e) {
			throw new RuntimeException("Failed to create mnemonic code", e);
		}
	}
	
	@Override
	public void validateMnemonicWords(List<String> mnemonicWords) {
		if(mnemonicWords == null) {
			throw new IllegalArgumentException("Provided mnemonic word list is null");
		} 

		if(mnemonicWords.size() < MNEMONIC_LENGTH_MIN) {
			throw new IllegalArgumentException(
					String.format("Provided mnemonic word list contains less than %i words", MNEMONIC_LENGTH_MIN));
		}

		if(mnemonicWords.size() > MNEMONIC_LENGTH_MAX) {
			throw new IllegalArgumentException(
					String.format("Provided mnemonic word list contains more than %i words", MNEMONIC_LENGTH_MAX));
		}

		if(mnemonicWords.size() %3 != 0) {
			throw new IllegalArgumentException("Provided the number of words for the mnemonic word list is not a multiple of 3");
		}
	}
}
