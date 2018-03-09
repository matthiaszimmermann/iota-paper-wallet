package org.matthiaszimmermann.crypto.core;

import java.io.File;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.bitcoin.BitcoinWallet;
import org.matthiaszimmermann.crypto.ethereum.EthereumWallet;
import org.matthiaszimmermann.crypto.iota.IotaWallet;
import org.matthiaszimmermann.crypto.utility.FileUtility;

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
		case Ethereum: 
			return new EthereumWallet(mnemonicWords, passPhase, network);
		case Iota: 
			return new IotaWallet(mnemonicWords, passPhase, network);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}
	
	public static Wallet getInstance(File file, String passPhrase) throws Exception {
		if(passPhrase == null) {
			throw new IllegalArgumentException("Pass phrase needs to be specified");
		}
		
		Technology technology = getTechnology(file);
		
		switch(technology) {
		case Bitcoin:
			return new BitcoinWallet(file, passPhrase);
		case Ethereum:
			return new EthereumWallet(file, passPhrase);
		case Iota: 
			return new IotaWallet(file, passPhrase);
		default:
			throw new IllegalArgumentException(String.format("Technology %s is currently not supported", technology));
		}
	}

	private static Technology getTechnology(File file) {
		JSONObject node = readJsonFile(file);
		
		// TODO find better solution for ethereum wallet
		if(!node.has(Wallet.JSON_TECHNOLOGY)) {
			return Technology.Ethereum;
		}
		
		return Technology.get(node.getString(Wallet.JSON_TECHNOLOGY));
	}

	private static JSONObject readJsonFile(File file) {
		String jsonString = FileUtility.readTextFile(file);
		
		if(jsonString.isEmpty()) {
			throw new JSONException("Empty wallet file");
		}

		return new JSONObject(jsonString);
	}
}
