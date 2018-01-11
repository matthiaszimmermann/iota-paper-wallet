package org.matthiaszimmermann.crypto.common;

public class IotaAccount extends Account {
	
	public static final int SECURITY_LEVEL_DEFAULT = 2;
	public static final boolean CHECKSUM_DEFAULT = true;

	public IotaAccount(String secret, String address, Network network) {
		this(secret, address, new Iota(network));
	}
	
	protected IotaAccount(String secret, String address, Protocol protocol) {
		super(secret, address, protocol);
	}

}
