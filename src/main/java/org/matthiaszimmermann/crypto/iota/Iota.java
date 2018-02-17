package org.matthiaszimmermann.crypto.iota;

import java.io.IOException;
import java.util.List;

import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.Entropy;
import org.matthiaszimmermann.crypto.common.Mnemonic;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;
import org.matthiaszimmermann.crypto.common.Seed;
import org.matthiaszimmermann.crypto.common.Technology;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

// TODO transfer creation /w offline signing
// http://ogrelab.ikratko.com/sending-new-transfer-to-iota-node-using-java-aka-sendtransfer/
public class Iota extends Protocol {

	public Iota(Network network) {
		super(Technology.Iota, network);
	}

	@Override
	public Account restoreAccount(List<String> mnemonic, String passphrase) {
		String seed = Seed.toIotaSeed(mnemonic, passphrase);
		String address = deriveAddressFromSeed(seed);
		
		return new IotaAccount(seed, address, getNetwork());
	}
	
	// https://github.com/modum-io/tokenapp-keys-iota/blob/master/src/main/java/io/modum/IotaAddressGenerator.java
	public static String deriveAddressFromSeed(String seed) {
		ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
		int index = 0;

		try {			
			return IotaAPIUtils.newAddress(
					seed, 
					IotaAccount.SECURITY_LEVEL_DEFAULT,
					index, 
					IotaAccount.CHECKSUM_DEFAULT,
					curl);
		} 
		catch (ArgumentException e) {
			throw new IllegalArgumentException(e);
		}
	} 
	
	@Override
	public List<String> generateMnemonicWords() {
		byte [] entropy = Entropy.generateEntropy();
		List<String> wordList = null;

		try {
			wordList = Mnemonic.loadWordList();
		} catch (IOException e) {
			throw new RuntimeException("Failed to load mnemonic default word list");
		}

		return Mnemonic.toWords(entropy, wordList);
	}

	@Override
	public void validateMnemonicWords(List<String> mnemonicWords) {
		// TODO add some validation here. if something looks bad throw an illegal arg exception	
	}

}
