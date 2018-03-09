package org.matthiaszimmermann.crypto.core;

public enum Technology {
	Bitcoin, 
	Ethereum, 
	Iota;
	
	public static Technology get(String name) {
		if(name == null || name.length() == 0) {
			throw new IllegalArgumentException("Provided name must not be null or empty");
		}
		
		String query = name.toLowerCase();
		
		if(Bitcoin.name().toLowerCase().equals(query)) {
			return Bitcoin;
		}
		else if(Ethereum.name().toLowerCase().equals(query)) {
			return Ethereum;
		}
		else if(Iota.name().toLowerCase().equals(query)) {
			return Iota;
		}
		else {
			throw new IllegalArgumentException("Unknown technology:" + name);
		}
	}
}
