package org.matthiaszimmermann.crypto.core;

import org.matthiaszimmermann.crypto.bitcoin.Bitcoin;
import org.matthiaszimmermann.crypto.ethereum.Ethereum;
import org.matthiaszimmermann.crypto.iota.Iota;

public class ProtocolFactory {

	public static Protocol getInstance(Technology technology, Network network) {
		switch(technology) {
		case Bitcoin: 
			return new Bitcoin(network);
		case Ethereum: 
			return new Ethereum(network);
		case Iota: 
			return new Iota(network);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}

}
