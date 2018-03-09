package org.matthiaszimmermann.crypto.iota;

import java.io.IOException;
import java.util.List;
import java.util.Random;

import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Entropy;
import org.matthiaszimmermann.crypto.core.Mnemonic;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.PBKDF2SHA512;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.Technology;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

// TODO transfer creation /w offline signing
// http://ogrelab.ikratko.com/sending-new-transfer-to-iota-node-using-java-aka-sendtransfer/
public class Iota extends Protocol {
	
	public static final int SEED_LENGTH = 81;
	public static final String TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	private static final int PBKDF2_ROUNDS = 2048;
	private static final String SALT_PREFIX = "mnemonic";

	public Iota(Network network) {
		super(Technology.Iota, network);
	}

	@Override
	public Account restoreAccount(List<String> mnemonic, String passphrase) {
		String seed = deriveSeedFromMnemonic(mnemonic, passphrase);
		String address = deriveAddressFromSeed(seed);
		
		return new IotaAccount(seed, address, getNetwork());
	}
	
	//  https://www.reddit.com/r/Iota/comments/70srbt/an_easy_way_to_generate_a_seed_with_java_on/
	private String deriveSeedFromMnemonic(List<String> words, String passphrase) {
		// 81 places 27 chars per place
		// 8 bytes per long in java
		// 
		String pass = String.join(" ", words);
		String salt = SALT_PREFIX + passphrase;

		byte[] byteSeed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, SEED_LENGTH * 8);
		StringBuffer seed = new StringBuffer();

		for(int i = 0; i < SEED_LENGTH; i++) {
			Random r = new Random(bytesToLong(byteSeed, i * 8));
			char c = TRYTE_ALPHABET.charAt(r.nextInt(27));
			seed.append(c);
		}

		return seed.toString();
	}

	/**
	 * https://stackoverflow.com/questions/4485128/how-do-i-convert-long-to-byte-and-back-in-java
	 */
	private static long bytesToLong(byte[] b, int offset) {
		long result = 0;
		for (int i = 0; i < 8; i++) {
			result <<= 8;
			result |= (b[i + offset] & 0xFF);
		}
		return result;
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
