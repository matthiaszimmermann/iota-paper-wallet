package org.matthiaszimmermann.crypto.pwg.iota;

import java.io.IOException;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

/**
 * Original source: 
 * https://github.com/modum-io/tokenapp-keys-iota/blob/master/src/main/java/io/modum/IotaAddressGenerator.java
 */
public class AddressGenerator {

	public static void main(String[] args) throws IOException, ArgumentException {
		final int SECURITY_LEVEL = 3;

		final String usage = "java -jar iota-keys.jar [<81 length seed> [<no of addresses>]]";

		if (args.length >= 1 && args[0].equals("-h")) {
			System.out.println("Please specify Seed: " + usage);
			System.exit(0);
		}

		String seed = null;

		if (args.length == 0) {
			seed = SeedGenerator.getNextSeed();
			System.out.println("Using generated seed: " + seed);
		}
		else {
			seed = args[0];
		}

		if (!seed.matches("[A-Z9]{81}")) {
			System.err.println("Seed must be 81 characters long and only contain uppercase letters and '9'");
			System.exit(1);
		}

		int addressCount = 3;

		if (args.length < 2) {
			System.out.println("Generating single address");
		}
		else {
			try {
				addressCount = Integer.valueOf(args[1]);
				if (addressCount < 0) {
					throw new NumberFormatException();
				}
			} 
			catch(NumberFormatException e) {
				System.err.println("Invalid number of addresses: " + usage);
				System.exit(1);
			}
		}

		for(int i = 0; i < addressCount; i++) {
			ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
			String address = IotaAPIUtils.newAddress(seed, SECURITY_LEVEL, i, true, curl);
			System.out.println(String.format("%d %s", i, address));
		}
	}
}
