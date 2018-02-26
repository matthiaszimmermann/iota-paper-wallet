package org.matthiaszimmermann.crypto.common;

import java.io.File;
import java.util.List;

import org.matthiaszimmermann.crypto.bitcoin.BitcoinWallet;
import org.matthiaszimmermann.crypto.iota.IotaWallet;

public class WalletFactory {

	public static Wallet getInstance(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
		if(mnemonicWords == null) {
			throw new IllegalArgumentException("Mnemonic words must not be null");
		}
		
		Technology technology = protocol.getTechnology();
		Network network = protocol.getNetwork();
		
		switch(technology) {
		case Bitcoin: 
			return new BitcoinWallet(mnemonicWords, passPhase, network);
		case Iota: 
			return new IotaWallet(mnemonicWords, passPhase, network);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}
	
	public static Wallet getInstance(File file, List<String> mnemonicWords, String passPhrase, Protocol protocol) throws Exception {
		
		if(mnemonicWords == null && passPhrase == null) {
			throw new IllegalArgumentException("Either mhemonics or pass phrase needs to be specified");
		}
		
		if(protocol == null) {
			throw new IllegalArgumentException("Protocol must not be null");
		}
		
		Technology technology = protocol.getTechnology();
		
		switch(protocol.getTechnology()) {
		case Bitcoin:
			return new BitcoinWallet(file, mnemonicWords, passPhrase);
		case Iota: 
			return new IotaWallet(file, mnemonicWords, passPhrase);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}

}
