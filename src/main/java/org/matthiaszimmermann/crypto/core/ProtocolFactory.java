package org.matthiaszimmermann.crypto.core;

import java.io.File;

import org.json.JSONException;
import org.json.JSONObject;
import org.matthiaszimmermann.crypto.bitcoin.Bitcoin;
import org.matthiaszimmermann.crypto.ethereum.Ethereum;
import org.matthiaszimmermann.crypto.iota.Iota;
import org.matthiaszimmermann.crypto.utility.FileUtility;

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

	public static Protocol getInstance(File walletFile) {
		JSONObject node = readJsonFile(walletFile);

		try {
			Technology technology = Technology.get(node.getString(Wallet.JSON_TECHNOLOGY));
			Network network= Network.get(node.getString(Wallet.JSON_NETWORK));

			return getInstance(technology, network);
		}
		catch(JSONException e) {
			throw new RuntimeException("Failed to access technology value", e);
		}
	}

	private static JSONObject readJsonFile(File file) {
		String jsonString = FileUtility.readTextFile(file);

		if(jsonString.isEmpty()) {
			throw new RuntimeException("Empty wallet file");
		}

		try {
			return new JSONObject(jsonString);
		}
		catch (JSONException e) {
			throw new RuntimeException("Failed to convert wallet file to json object", e);
		}
	}

}
