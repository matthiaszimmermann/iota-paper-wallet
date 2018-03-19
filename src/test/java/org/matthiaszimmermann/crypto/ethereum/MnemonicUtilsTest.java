package org.matthiaszimmermann.crypto.ethereum;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.core.Bip39TestVectors;
import org.web3j.crypto.MnemonicUtils;

public class MnemonicUtilsTest extends BaseTest {
	public static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	public static final byte [] ENTROPY_BYTES_16 =  {108, 59, 35, 9, 90, 110, 57, -31, -118, 77, 104, 118, -89, 58, -21, 121};
	public static final String ENTROPY_WORDS_16 = "history suit seat regular toe valid circle public issue degree river vendor";
	
	@Ignore("Test fails as web3j 3.3.1 fails to read its own mnemonic word list file: en-mnemonic-word-list.txt")
	@Test
	public void testMnemonicFixed16() throws Exception {
		String mnemonicSentence = MnemonicUtils.generateMnemonic(ENTROPY_BYTES_16);

		assertEquals(ENTROPY_WORDS_16, mnemonicSentence);
	}

	@Ignore("Test fails as web3j 3.3.1 fails to read its own mnemonic word list file: en-mnemonic-word-list.txt")
	@Test
	public void testBip39Vectors() throws Exception {
		log("--- start testBip39Vectors() ---");
		
		Bip39TestVectors vectors = new Bip39TestVectors();
		int n = vectors.length();
		int okMnemonic = 0;
		
		// run through all test cases of the BIP39 reference implementation
		for(int i = 0; i < n; i++) {
			byte [] entropy = vectors.getEntropy(i);
			String mnemonicExpected = vectors.getMnemonic(i);
			String mnemonicSentence = MnemonicUtils.generateMnemonic(entropy);
			String entropyHex = entropyToString(entropy);
			
			if(!mnemonicExpected.equals(mnemonicSentence)) {
				log("bip 39 vector [%d]: mismatch: for '%s' expected: '%s', but found: '%s'", i, entropyHex, mnemonicExpected, mnemonicSentence);
			}
			else {
				log("bip 39 vector [%d] ok: entropy: '%s', mnemonic: '%s'", i, entropyHex, mnemonicSentence);
				okMnemonic++;
			}
		} 
		
		assertEquals("some entropy->mnemonic cases failed", n, okMnemonic);
		
		log("--- start testBip39Vectors() ---");
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
