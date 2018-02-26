package org.matthiaszimmermann.crypto.iota;

import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.Network; 

public class IotaAccount extends Account {
	
	public static final int SECURITY_LEVEL_DEFAULT = 2;
	public static final boolean CHECKSUM_DEFAULT = true;

	public IotaAccount(String secret, String address, Network network) {
		super(secret, address, new Iota(network));
	}
}
