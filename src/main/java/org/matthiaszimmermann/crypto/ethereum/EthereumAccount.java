package org.matthiaszimmermann.crypto.ethereum;

import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network; 

public class EthereumAccount extends Account {
	
	public EthereumAccount(String secret, String address, Network network) {
		super(secret, address, new Ethereum(network));
	}
}
