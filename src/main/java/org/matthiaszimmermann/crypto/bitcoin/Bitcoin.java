package org.matthiaszimmermann.crypto.bitcoin;

import java.io.IOException;
import java.util.List;

import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.params.UnitTestParams;
import org.matthiaszimmermann.crypto.common.Entropy;
import org.matthiaszimmermann.crypto.common.Mnemonic;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;
import org.matthiaszimmermann.crypto.common.Technology;

public class Bitcoin extends Protocol {

	public static final int MNEMONIC_LENGTH_MIN = 12;
	public static final int MNEMONIC_LENGTH_MAX = 24;

	// TODO cleanup
//	public static final int PBKDF2_ROUNDS = 2048;
//	public static final String SALT_PREFIX = "mnemonic";

	public Bitcoin(Network network) {
		super(Technology.Bitcoin, network);
	}

	@Override
	public BitcoinAccount restoreAccount(List<String> mnemonic, String passphrase) {		
		// TODO (1) check if we need/should provide the passphrase as 2nd argument
		// TODO (2) decide if MnemonicCode should be moved into cryptoj core
		byte[] seed = MnemonicCode.toSeed(mnemonic, "");

		DeterministicKey dkKey = HDKeyDerivation.createMasterPrivateKey(seed);
		DeterministicKey dKey = HDKeyDerivation.deriveChildKey(dkKey, 44 | ChildNumber.HARDENED_BIT);
		DeterministicKey dkRoot = HDKeyDerivation.deriveChildKey(dKey, ChildNumber.HARDENED_BIT);

		return new BitcoinAccount(dkRoot, 0, getNetwork());
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
	
	// To create binary seed from mnemonic, we use PBKDF2 function
	// with mnemonic sentence (in UTF-8) used as a password and
	// string "mnemonic" + passphrase (again in UTF-8) used as a
	// salt. Iteration count is set to 4096 and HMAC-SHA512 is
	// used as a pseudo-random function. Desired length of the
	// derived key is 512 bits (= 64 bytes).
//	private byte[] toSeed(List<String> mnemonic, String passphrase) {
//		int len = (mnemonic.size() / 3) * 4;
//
//		String pass = String.join(" ", mnemonic);
//		String salt = SALT_PREFIX + passphrase;
//
//		return PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, len);
//	}

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
