package org.matthiaszimmermann.crypto.ethereum;

import java.util.List;

import org.bitcoinj.crypto.MnemonicCode;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Entropy;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

public class Ethereum extends Protocol {

	public static final int MNEMONIC_LENGTH_MIN = 12;
	public static final int MNEMONIC_LENGTH_MAX = 24;

	public Ethereum(Network network) {
		super(Technology.Ethereum, network);
	}

//	public static NetworkParameters getNetworkParameters(Network network) {
//		if(Network.Production.equals(network)) {
//			return MainNetParams.get();
//		}
//		else if(Network.Test.equals(network)) {
//			return TestNet3Params.get();
//		}
//		else {
//			return UnitTestParams.get();
//		}
//	}

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

	@Override
	public Account restoreAccount(List<String> mnemonicWords, String passPhrase) {
		String privateKey = derivePrivateKeyFromMnemonics(mnemonicWords, passPhrase);
		String address = deriveAddressFromPrivateKey(privateKey);
		
		return new EthereumAccount(privateKey, address, getNetwork());
	}
	
	/**
	 * Returns the private key (hex string with prefix) derived from the provided mnemonic words 
	 * @param mnemonicWords
	 * @param passPhrase
	 */
	public String derivePrivateKeyFromMnemonics(List<String> mnemonicWords, String passPhrase) {
		String mnemonic = String.join(" ", mnemonicWords);
		byte [] seed = MnemonicUtils.generateSeed(mnemonic, passPhrase);
		byte [] privateKeyBytes = Hash.sha256(seed);
		ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
		
		return Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
	}
	
	/**
	 * Returns the address for the provided private key  
	 * @param privateKey (hex string with prefix)
	 * @param passPhrase
	 */
	public String deriveAddressFromPrivateKey(String privateKey) {
		Credentials credentials = Credentials.create(privateKey);
		
		return credentials.getAddress();
	}
	
}
