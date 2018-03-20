package org.matthiaszimmermann.crypto.iota;

import java.util.List;
import java.util.Random;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network; 

public class IotaAccount extends Account {
	
	public static final int SEED_LENGTH = 81;
	
	private static final int PBKDF2_ROUNDS = 2048;
	private static final String SALT_PREFIX = "mnemonic";
	
	public static final int SECURITY_LEVEL_DEFAULT = 2;
	public static final boolean CHECKSUM_DEFAULT = true;

	public IotaAccount(List<String> mnemonic, String passPhrase, Network network) {
		super(passPhrase, new Iota(network));
		
		secret = deriveSeedFromMnemonic(mnemonic);
		address = Iota.deriveAddressFromSeed(secret);
	}
	
	public IotaAccount(JSONObject accountJson, String passPhrase, Network network) throws JSONException {
		super(accountJson, passPhrase, new Iota(network));
	}
	
	//  https://www.reddit.com/r/Iota/comments/70srbt/an_easy_way_to_generate_a_seed_with_java_on/
	private String deriveSeedFromMnemonic(List<String> words) {
		// 81 places 27 chars per place
		// 8 bytes per long in java
		// 
		String pass = String.join(" ", words);
		String salt = SALT_PREFIX + passPhrase;

		byte[] byteSeed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, SEED_LENGTH * 8);
		StringBuffer seed = new StringBuffer();

		for(int i = 0; i < SEED_LENGTH; i++) {
			Random r = new Random(bytesToLong(byteSeed, i * 8));
			char c = Iota.TRYTE_ALPHABET.charAt(r.nextInt(27));
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
