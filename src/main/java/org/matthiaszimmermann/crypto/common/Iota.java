package org.matthiaszimmermann.crypto.common;

import java.util.List;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

public class Iota extends Protocol {

	public Iota(Network network) {
		super(Technology.Iota, network);
	}

	protected Iota(Technology technology, Network network) {
		super(technology, network);
	}

	@Override
	public Account restoreAccount(List<String> mnemonic, String passphrase) {
		String seed = Seed.toIotaSeed(mnemonic, passphrase);
		String address = null;
		
		ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
		int index = 0;

		try {			
			address = IotaAPIUtils.newAddress(
					seed, 
					IotaAccount.SECURITY_LEVEL_DEFAULT,
					index, 
					IotaAccount.CHECKSUM_DEFAULT,
					curl);
		} 
		catch (ArgumentException e) {
			throw new IllegalArgumentException(e);
		}
		
		return new IotaAccount(seed, address, getNetwork());
	}

}
