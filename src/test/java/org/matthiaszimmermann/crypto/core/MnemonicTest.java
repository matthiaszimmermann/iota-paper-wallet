package org.matthiaszimmermann.crypto.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.utility.EntropyUtility;

public class MnemonicTest extends BaseTest {
	public static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	public static final byte [] ENTROPY_BYTES_16 =  {108, 59, 35, 9, 90, 110, 57, -31, -118, 77, 104, 118, -89, 58, -21, 121};
	public static final String ENTROPY_WORDS_16 = "history suit seat regular toe valid circle public issue degree river vendor";

	@Test
	public void testBip39Vectors() throws Exception {
		log("--- start testBip39Vectors() ---");
		
		Bip39TestVectors vectors = new Bip39TestVectors();
		int n = vectors.length();
		int okMnemonic = 0;
		int okEntropy = 0;
		
		// run through all test cases of the BIP39 reference implementation
		for(int i = 0; i < n; i++) {
			byte [] entropy = vectors.getEntropy(i);
			String mnemonicExpected = vectors.getMnemonic(i);
			
			List<String> mnemonicWords = Mnemonic.deriveWords(entropy);
			String mnemonicSentence = String.join(" ", mnemonicWords);
			String entropyHex = entropyToString(entropy);
			
			if(!mnemonicExpected.equals(mnemonicSentence)) {
				log("bip 39 vector [%d]: mismatch: for '%s' expected: '%s', but found: '%s'", i, entropyHex, mnemonicExpected, mnemonicSentence);
			}
			else {
				log("bip 39 vector [%d] ok: entropy: '%s', mnemonic: '%s'", i, entropyHex, mnemonicSentence);
				okMnemonic++;
			}
			
			byte [] derivedEntropy = Mnemonic.deriveEntropy(mnemonicWords);
			String derivedEntropyHex = entropyToString(derivedEntropy);
			
			if(!entropyHex.equals(derivedEntropyHex)) {
				log("bip 39 vector [%d]: expected entropy: '%s', bug found: '%s' for mnemonic: '%s'", i, entropyHex, derivedEntropyHex, mnemonicSentence);
			}
			else {
				okEntropy++;
			}
		} 
		
		assertEquals("some entropy->mnemonic cases failed", n, okMnemonic);
		assertEquals("some mnemonic->entropy cases failed", n, okEntropy);
		
		log("--- start testBip39Vectors() ---");
	}
	
	@Test
	public void testMnemonicFixed16() throws Exception {
		List<String> mnemonicWords = Mnemonic.deriveWords(ENTROPY_BYTES_16);
		String mnemonicSentence = Mnemonic.convert(mnemonicWords);

		assertEquals(ENTROPY_WORDS_16, mnemonicSentence);

		byte [] entropy = Mnemonic.deriveEntropy(mnemonicWords);

		assertArrayEquals(ENTROPY_BYTES_16, entropy);
	}

	@Test
	public void testMnemonicRandom() throws Exception {
		log("--- start testMnemonicRandom() ---");

		byte [] entropy = EntropyUtility.generateEntropy();
		List<String> words = Mnemonic.deriveWords(entropy);;

		assertNotNull(words);
		assertTrue(words.size() > 0);

		log("entropy: " + entropyToString(entropy));
		log("words: " + Mnemonic.convert(words));

		byte[] entropyFromWords = Mnemonic.deriveEntropy(words);

		assertArrayEquals(entropy, entropyFromWords);

		log("--- end testMnemonicRandom() ---");
	}

	private String entropyToString(byte [] entropy) {
		if(entropy == null || entropy.length == 0) {
			return "{}";
		}

		StringBuffer buf = new StringBuffer("{");

		for(int i = 0; i < entropy.length; i++) {
			if(i > 0) {
				buf.append(", ");
			}

			buf.append(entropy[i]);
		}

		return buf.toString() + "}";
	}
}
