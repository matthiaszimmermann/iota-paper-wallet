package org.matthiaszimmermann.crypto.bitcoin;

import java.util.List;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Entropy;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;

public class Bitcoin extends Protocol {

	public static final int MNEMONIC_LENGTH_MIN = 12;
	public static final int MNEMONIC_LENGTH_MAX = 24;

	public Bitcoin(Network network) {
		super(Technology.Bitcoin, network);
	}

	@Override
	public BitcoinAccount createAccount(List<String> mnemonic, String passPhrase) {		
		return new BitcoinAccount(mnemonic, passPhrase, getNetwork());
	}

	@Override
	public Account restoreAccount(JSONObject accountJson, String passPhrase) {
		try {
			return new BitcoinAccount(accountJson, passPhrase, getNetwork());
		} 
		catch (JSONException e) {
			throw new RuntimeException("Failed to create Bitcoin account from json object", e);
		}
	}

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

		try { 
			MnemonicCode.toSeed(mnemonicWords, "dummy");
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Provided mnemonic word list fails to verify: ", e);
		}
	}

	public static NetworkParameters getNetworkParameters(Network network) {
		if(Network.Production.equals(network)) {
			return MainNetParams.get();
		}
		else if(Network.Test.equals(network)) {
			return TestNet3Params.get();
		}
		else {
			return UnitTestParams.get();
		}
	}

	// TODO check/verify to create segwit keys, see
	// https://www.reddit.com/r/Electrum/comments/7dku5r/segwit_wallets_and_electrum/
	// hypothesis only need to change constant 44 to 49
	public DeterministicKey seedToRootKey(byte [] seed) {
		DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed);
		DeterministicKey childKey = HDKeyDerivation.deriveChildKey(masterPrivateKey, 44 | ChildNumber.HARDENED_BIT);

		return  HDKeyDerivation.deriveChildKey(childKey, ChildNumber.HARDENED_BIT);
	}
}
