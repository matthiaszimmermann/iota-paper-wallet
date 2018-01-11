package org.matthiaszimmermann.crypto.common;

import java.util.List;

public abstract class Protocol {
	
	private Technology technology;
	private Network network;
	
	protected Protocol(Technology technology, Network network) {
		
		if(technology == null) {
			throw new IllegalArgumentException("Technology must not be null");
		}
		
		if(network == null) {
			throw new IllegalArgumentException("Network must not be null");
		}
		
		this.technology = technology;
		this.network = network;
	}
	
	public Technology getTechnology() {
		return technology;
	}
	
	public Network getNetwork() {
		return network;
	}
	
	abstract public Account restoreAccount(List<String> mnemonic, String passphrase);
}
