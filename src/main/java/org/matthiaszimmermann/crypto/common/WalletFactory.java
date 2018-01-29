package org.matthiaszimmermann.crypto.common;

import java.io.File;
import java.util.List;

public class WalletFactory {

	public static Wallet getInstance(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
		Technology technology = protocol.getTechnology();
		Network network = protocol.getNetwork();
		
		switch(technology) {
		case Iota: 
			return new IotaWallet(mnemonicWords, passPhase, network);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}
	
	public static Wallet getInstance(File file, String passPhrase, Protocol protocol) throws Exception {
		
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
		Technology technology = protocol.getTechnology();
		
		switch(protocol.getTechnology()) {
		case Iota: 
			return new IotaWallet(file, passPhrase);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}

}
