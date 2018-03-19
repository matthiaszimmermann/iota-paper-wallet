package org.matthiaszimmermann.crypto.core;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author mzi
 */
public class Entropy {

	public static final int ENTROPY_BITS_DEFAULT = 128;

	/**
	 * Returns 128 bits/16 bytes of pseudo randomness.
	 * @return
	 */
	public static byte [] generateEntropy() {
		return generateEntropy(ENTROPY_BITS_DEFAULT);
	}
	
	/**
	 * Returns the specified number of bits of randomness.
	 * The implementation is based on {@link SecureRandom#getInstanceStrong()}
	 * @param desired number of random bits. Needs to be positive and a multiple of 8
	 * @return a random byte array
	 */
	public static byte [] generateEntropy(int bits) {
        
		if(bits < 0 || bits % 8 != 0) {
			throw new RuntimeException("Random bits needs to be positive (and a multiple of 8 bits) but is " + bits);
		}
		
        try {
            SecureRandom sr;
            sr = SecureRandom.getInstanceStrong();
            return sr.generateSeed(bits / 8);
        } 
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to create secure random instance", e);
        }
	}
}
