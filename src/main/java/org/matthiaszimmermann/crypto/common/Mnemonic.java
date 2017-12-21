package org.matthiaszimmermann.crypto.common;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/crypto/MnemonicCode.java
 * @author mzi
 *
 */
public class Mnemonic {

	private static final String BIP39_ENGLISH_RESOURCE_NAME = "wordlist/english.txt";
	private static final String BIP39_ENGLISH_SHA256 = "F0CB4EA7A446004209928D296C528C38FCE077F59A49BFD88EC6C9AAA37C48C4";

	private static final int SEED_LENGTH_BITCOIN = 64;
	private static final int SEED_LENGTH_IOTA = 81;

	private static final String DIGEST_ALGORITHM_SHA256 = "SHA-256";
	private static final int PBKDF2_ROUNDS = 2048;

	private static final String TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	private static final String SALT_PREFIX = "mnemonic";

	private ArrayList<String> wordList;

	/** 
	 * Initialize from the included word list.  
	 * @throws NoSuchAlgorithmException 
	 */
	public Mnemonic() throws IOException, NoSuchAlgorithmException {
		this(openDefaultWords(), BIP39_ENGLISH_SHA256);
	}

	/**
	 * Creates an MnemonicCode object, initializing with words read from the supplied input stream. 
	 * If a wordListDigest is supplied the digest of the words will be checked.
	 * @throws IOException
	 */
	public Mnemonic(InputStream wordStream, String wordListDigest) throws IOException {

		wordList = new ArrayList<>();
		MessageDigest md = getSHA256MessageDigest();

		try (DigestInputStream dis = new DigestInputStream(wordStream, md)) {
			BufferedReader br = new BufferedReader(new InputStreamReader(dis, "UTF-8"));
			String word;

			while ((word = br.readLine()) != null) {
				md.update(word.getBytes());
				wordList.add(word);
			}

			br.close();
		}

		byte[] digest = md.digest();

		if (wordList.size() != 2048) {
			throw new IllegalArgumentException("input stream did not contain 2048 words but " + wordList.size());
		}

		// If a wordListDigest is supplied check to make sure it matches.
		if (wordListDigest != null) {
			String hexdigest = bytesToHex(digest);

			if (!hexdigest.equals(wordListDigest)) {
				throw new IllegalArgumentException("wordlist digest mismatch for digest '" + hexdigest + "'");
			}
		}
	}

	public int words() {
		return wordList.size();
	}

	public String getWord(int index) {
		if(index < 0 || index > wordList.size() - 1) {
			return null;
		}

		return wordList.get(index);
	}
	
	public byte [] generateEntropy() {
		return generateEntropy(128);
	}
	
	public byte [] generateEntropy(int bits) {
        
		if(bits < 0 || bits % 8 != 0) {
			logError(new RuntimeException(), "Random bits needs to be positive and a multiple of 8 bits but is " + bits);
		}
		
        try {
            SecureRandom sr;
            sr = SecureRandom.getInstanceStrong();
            return sr.generateSeed(bits / 8);
        } 
        catch (NoSuchAlgorithmException e) {
            logError(e, "Failed to create secure random instance");
            return null;
        }
	}

	/**
	 * Convert entropy data to mnemonic word list.
	 * @throws NoSuchAlgorithmException 
	 */
	public List<String> toMnemonic(byte[] entropy) throws IllegalArgumentException {
		if (entropy.length % 4 > 0)
			throw new IllegalArgumentException("Entropy length not multiple of 32 bits.");

		if (entropy.length == 0)
			throw new IllegalArgumentException("Entropy is empty.");

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

			words.add(this.wordList.get(index));
		}

		return words;        
	}

	/**
	 * Check to see if a mnemonic word list is valid.
	 */
	public void check(List<String> words) throws IllegalArgumentException {
		toEntropy(words);
	}

	/**
	 * Convert mnemonic word list to original entropy value.
	 */
	public byte[] toEntropy(List<String> words) throws IllegalArgumentException {
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


	/**
	 * Convert mnemonic word list to Bitcoin seed.
	 */
	public static byte[] toBitcoinSeed(List<String> words, String passphrase) {

		// To create binary seed from mnemonic, we use PBKDF2 function
		// with mnemonic sentence (in UTF-8) used as a password and
		// string "mnemonic" + passphrase (again in UTF-8) used as a
		// salt. Iteration count is set to 4096 and HMAC-SHA512 is
		// used as a pseudo-random function. Desired length of the
		// derived key is 512 bits (= 64 bytes).
		//
		String pass = String.join(" ", words);
		String salt = SALT_PREFIX + passphrase;

		byte[] seed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, SEED_LENGTH_BITCOIN);

		return seed;
	}

	public static String toIotaSeed(List<String> words, String passphrase) {
		// 81 places 27 chars per place
		// 8 bytes per long in java
		// 
		String pass = String.join(" ", words);
		String salt = SALT_PREFIX + passphrase;

		byte[] byteSeed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, SEED_LENGTH_IOTA * 8);
		StringBuffer seed = new StringBuffer();

		for(int i = 0; i < SEED_LENGTH_IOTA; i++) {
			Random r = new Random(bytesToLong(byteSeed, i * 8));
			char c = TRYTE_ALPHABET.charAt(r.nextInt(27));
			seed.append(c);
		}

		return seed.toString();
	}

	private static InputStream openDefaultWords() throws IOException {
		InputStream stream = Mnemonic.class.getResourceAsStream(BIP39_ENGLISH_RESOURCE_NAME);

		if (stream == null) {
			throw new FileNotFoundException(BIP39_ENGLISH_RESOURCE_NAME);
		}

		return stream;
	}

	private MessageDigest getSHA256MessageDigest() {
		try {
			return MessageDigest.getInstance(DIGEST_ALGORITHM_SHA256);
		} 
		catch (NoSuchAlgorithmException e) {
			logError(e, "Digest algorithm not found: " + DIGEST_ALGORITHM_SHA256);
		}

		return null;
	}

	private void logError(Exception e, String message) {
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
}
