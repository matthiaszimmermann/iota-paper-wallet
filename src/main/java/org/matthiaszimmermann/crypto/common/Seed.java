package org.matthiaszimmermann.crypto.common;

import java.util.List;
import java.util.Random;

/**
 * @author mzi
 */
public class Seed {

	public static final int SEED_LENGTH_BITCOIN = 64;
	public static final int SEED_LENGTH_IOTA = 81;

	private static final int PBKDF2_ROUNDS = 2048;
	private static final String IOTA_TRYTE_ALPHABET = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String SALT_PREFIX = "mnemonic";

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
			char c = IOTA_TRYTE_ALPHABET.charAt(r.nextInt(27));
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
}
