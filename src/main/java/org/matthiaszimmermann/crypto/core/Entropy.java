package org.matthiaszimmermann.crypto.core;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author mzi
 */
public class Entropy {

	public static final int ENTROPY_BITS_DEFAULT = 128;

	public static byte [] generateEntropy() {
		return generateEntropy(ENTROPY_BITS_DEFAULT);
	}
	
	public static byte [] generateEntropy(int bits) {
        
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

	private static void logError(Exception e, String message) {
		System.err.println(message);
		e.printStackTrace();
		System.exit(-1);
	}
}
