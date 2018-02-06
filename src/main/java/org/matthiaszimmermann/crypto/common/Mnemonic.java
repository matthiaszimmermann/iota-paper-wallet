package org.matthiaszimmermann.crypto.common;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/crypto/MnemonicCode.java
 * @author mzi
 *
 */
public class Mnemonic {

	public static final String BIP39_ENGLISH_RESOURCE_NAME = "wordlist/english.txt";
	public static final String BIP39_ENGLISH_SHA256 = "0F91DA80C002DB0F322D2BFA7040CD4E972872C1B830CC233173207E4EECA326";
	public static final int BIP39_ENGLISH_WORDS = 2048;

	private static final String DIGEST_ALGORITHM_SHA256 = "SHA-256";
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

	//private ArrayList<String> wordList;

	/**
	 * Returns the official BIP39 English word list.
	 * @throws IOException
	 */
	public static List<String> loadWordList() throws IOException {
		List<String> words = loadWordList(openBip39Words(), BIP39_ENGLISH_SHA256);
		
		if (words.size() != BIP39_ENGLISH_WORDS) {
			throw new IllegalArgumentException("input stream did not contain " + BIP39_ENGLISH_WORDS + " words but " + words.size());
		}

		return words;
	}
	
	/**
	 * Returns the word list obtained form the provided word stream and verifies it with the provided digest.
	 */
	public static List<String> loadWordList(InputStream wordStream, String wordListDigest) throws IOException {
		List<String> words = new ArrayList<>();
		
		MessageDigest md = getSHA256MessageDigest();

		try (DigestInputStream dis = new DigestInputStream(wordStream, md)) {
			BufferedReader br = new BufferedReader(new InputStreamReader(dis, "UTF-8"));
			String word;

			while ((word = br.readLine()) != null) {
				md.update(word.getBytes());
				words.add(word);
			}

			br.close();
		}

		// If a wordListDigest is supplied check to make sure it matches.
		if (wordListDigest != null) {
			String hexdigest = bytesToHex(md.digest());

			if (!hexdigest.equals(wordListDigest)) {
				throw new IllegalArgumentException("wordlist digest mismatch for digest '" + hexdigest + "'");
			}
		}
		
		return words;
	}

	/**
	 * Convert entropy data to mnemonic word list.
	 * @throws NoSuchAlgorithmException 
	 */
	public static List<String> toWords(byte[] entropy, List<String> wordList) throws IllegalArgumentException {
		if(entropy.length == 0) {
			throw new IllegalArgumentException("Entropy is empty.");
		}
		
		if(entropy.length % 4 > 0) {
			throw new IllegalArgumentException("Entropy length not multiple of 32 bits.");
		}
		
		if(wordList == null) {
			throw new IllegalArgumentException("Word list is empty/null.");
		}
		
		if(wordList.size() != BIP39_ENGLISH_WORDS) {
			throw new IllegalArgumentException("Bad word list size. Only supported size is " +BIP39_ENGLISH_WORDS);
		}

		// We take initial entropy of ENT bits and compute its
		// checksum by taking first ENT / 32 bits of its SHA256 hash.

		byte[] hash = getSHA256MessageDigest().digest(entropy);
		boolean[] hashBits = bytesToBits(hash);

		boolean[] entropyBits = bytesToBits(entropy);
		int checksumLengthBits = entropyBits.length / 32;

		// We append these bits to the end of the initial entropy. 
		boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
		System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
		System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);

		// Next we take these concatenated bits and split them into
		// groups of 11 bits. Each group encodes number from 0-2047
		// which is a position in a wordlist.  We convert numbers into
		// words and use joined words as mnemonic sentence.

		ArrayList<String> words = new ArrayList<>();
		int nwords = concatBits.length / 11;

		for (int i = 0; i < nwords; ++i) {
			int index = 0;

			for (int j = 0; j < 11; ++j) {
				index <<= 1;
				if (concatBits[(i * 11) + j])
					index |= 0x1;
			}

			words.add(wordList.get(index));
		}

		return words;        
	}

	/**
	 * Check to see if a mnemonic word list is valid.
	 */
	public static void check(List<String> wordList, List<String> words) throws IllegalArgumentException {
		toEntropy(wordList, words);
	}
	
	/**
	 * Concatenates words to a space separated string.
	 */
	public static String convert(List<String> words) {
		return words == null ? null : String.join(" ", words);
	}
	
	/**
	 * Separates a sentence of space separated words into a list of its individual words.
	 */
	public static List<String> convert(String sentence) {
		return Arrays.asList(sentence.split(" "));
	}

	/**
	 * Convert mnemonic word list to original entropy value.
	 */
	public static byte[] toEntropy(List<String> words, List <String> wordList) throws IllegalArgumentException {
		if (words.size() % 3 > 0)
			throw new IllegalArgumentException("Word list size must be multiple of three words.");

		if (words.size() == 0)
			throw new IllegalArgumentException("Word list is empty.");

		// Look up all the words in the list and construct the
		// concatenation of the original entropy and the checksum.
		//
		int concatLenBits = words.size() * 11;
		boolean[] concatBits = new boolean[concatLenBits];
		int wordindex = 0;
		for (String word : words) {
			// Find the words index in the wordlist.
			int ndx = Collections.binarySearch(wordList, word);

			if (ndx < 0) {
				throw new IllegalArgumentException("Unkown word at word list position " + (wordindex + 1) + ":'" + word + "'");
			}

			// Set the next 11 bits to the value of the index.
			for (int ii = 0; ii < 11; ++ii) {
				concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
			}

			++wordindex;
		}        

		int checksumLengthBits = concatLenBits / 33;
		int entropyLengthBits = concatLenBits - checksumLengthBits;

		// Extract original entropy as bytes.
		byte[] entropy = new byte[entropyLengthBits / 8];
		for (int ii = 0; ii < entropy.length; ++ii)
			for (int jj = 0; jj < 8; ++jj)
				if (concatBits[(ii * 8) + jj])
					entropy[ii] |= 1 << (7 - jj);

		// Take the digest of the entropy.
		byte[] hash = getSHA256MessageDigest().digest(entropy);
		boolean[] hashBits = bytesToBits(hash);

		// Check all the checksum bits.
		for (int i = 0; i < checksumLengthBits; ++i)
			if (concatBits[entropyLengthBits + i] != hashBits[i])
				throw new IllegalArgumentException("Mnemonic checksum exception");

		return entropy;
	}


	private static InputStream openBip39Words() throws IOException {
		InputStream stream = Mnemonic.class.getResourceAsStream(BIP39_ENGLISH_RESOURCE_NAME);

		if (stream == null) {
			throw new FileNotFoundException(BIP39_ENGLISH_RESOURCE_NAME);
		}

		return stream;
	}

	private static MessageDigest getSHA256MessageDigest() {
		try {
			return MessageDigest.getInstance(DIGEST_ALGORITHM_SHA256);
		} 
		catch (NoSuchAlgorithmException e) {
			logError(e, "Digest algorithm not found: " + DIGEST_ALGORITHM_SHA256);
		}

		return null;
	}

	private static void logError(Exception e, String message) {
		System.err.println(message);
		e.printStackTrace();
		System.exit(-1);
	}

	/**
	 * https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	 */
	private static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];

		for( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}

		return new String(hexChars);
	}

	private static boolean[] bytesToBits(byte[] data) {
		boolean[] bits = new boolean[data.length * 8];
		for (int i = 0; i < data.length; ++i)
			for (int j = 0; j < 8; ++j)
				bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
		return bits;
	}
}
