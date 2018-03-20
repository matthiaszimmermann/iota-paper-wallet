package org.matthiaszimmermann.crypto.utility;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;

public class EntropyUtilityTest extends BaseTest {

	@Test
	public void testRandomness() throws Exception {
		Set<String> samples = new HashSet<>();
		int steps = 100000;

		for(int i = 0; i < steps; i++) {
			byte [] entropy = EntropyUtility.generateEntropy();
			String entropyEncoded = AesUtility.bytesToBase64(entropy);

			assertEquals("Unexpected entropy size", EntropyUtility.ENTROPY_BITS_DEFAULT/8, entropy.length);
			assertTrue(String.format("Identical entropy '%s' produced (step %d/%s)", entropyEncoded, i, steps), 
					!samples.contains(entropyEncoded));

			samples.add(entropyEncoded);
		}
	}

	@Test
	public void testRandomness16() throws Exception {
		log("--- start testRandomness16() ---");
		
		Set<String> samples = new HashSet<>();
		int entropyBits = 16;
		int steps = 66000;
		boolean found = false;

		for(int i = 0; i < steps && !found; i++) {
			byte [] entropy = EntropyUtility.generateEntropy(entropyBits);
			String entropyEncoded = AesUtility.bytesToBase64(entropy);

			assertEquals("Unexpected entropy size", entropyBits/8, entropy.length);

			if(samples.contains(entropyEncoded)) {
				log(String.format("Identical entropy '%s' produced (step %d/%s)", entropyEncoded, i, steps));
				found = true;
			}
			else {
				samples.add(entropyEncoded);
			}
		}
		
		assertTrue("Failed to create twice same entropy", found);
		
		log("--- end testRandomness16() ---");
	}

	@Test
	public void testRandomness256() throws Exception {
		Set<String> samples = new HashSet<>();
		int entropyBits = 256;
		int steps = 100000;

		for(int i = 0; i < steps; i++) {
			byte [] entropy = EntropyUtility.generateEntropy(entropyBits);
			String entropyEncoded = AesUtility.bytesToBase64(entropy);

			assertEquals("Unexpected entropy size", entropyBits/8, entropy.length);
			assertTrue(String.format("Identical entropy '%s' produced (step %d/%s)", entropyEncoded, i, steps), 
					!samples.contains(entropyEncoded));

			samples.add(entropyEncoded);
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParameterNegative() throws Exception {		
		EntropyUtility.generateEntropy(-1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParameterZero() throws Exception {		
		EntropyUtility.generateEntropy(0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParameterNotMultipleOf8() throws Exception {		
		EntropyUtility.generateEntropy(7);
	}
}
