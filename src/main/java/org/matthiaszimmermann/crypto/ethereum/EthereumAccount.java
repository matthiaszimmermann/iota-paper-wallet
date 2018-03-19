package org.matthiaszimmermann.crypto.ethereum;

import java.math.BigInteger;
import java.util.List;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.crypto.Wallet;
import org.web3j.crypto.WalletFile;
import org.web3j.utils.Numeric;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsonorg.JsonOrgModule; 

public class EthereumAccount extends Account {

	private static final ObjectMapper objectMapper = new ObjectMapper();

	static {
		objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		objectMapper.registerModule(new JsonOrgModule());	
	}

	Credentials credentials = null;

	public EthereumAccount(List<String> mnemonicWords, String passPhrase, Network network) {
		super(passPhrase, new Ethereum(network));
		
		secret = derivePrivateKeyFromMnemonics(mnemonicWords, passPhrase);
		credentials = Credentials.create(secret);
		address = deriveAddressFromPrivateKey(secret);
	}
	
	public EthereumAccount(JSONObject accountJson, String passPhrase, Network network) {
		super(passPhrase, new Ethereum(network));
		
		WalletFile walletFile = objectMapper.convertValue(accountJson, WalletFile.class);
		
		try {
			credentials = Credentials.create(Wallet.decrypt(passPhrase, walletFile));
			
			ECKeyPair keyPair = credentials.getEcKeyPair();
			BigInteger privateKey = keyPair.getPrivateKey();
			
			secret = Numeric.toHexStringWithPrefix(privateKey);
		    address = credentials.getAddress();
		    protocol = new Ethereum(network);
		} 
		catch (CipherException e) {
			throw new RuntimeException("Failed to create credentials from provided wallet json");
		}		
	}
	
	/**
	 * Returns the private key (hex string with prefix) derived from the provided mnemonic words 
	 * @param mnemonicWords
	 * @param passPhrase
	 */
	private String derivePrivateKeyFromMnemonics(List<String> mnemonicWords, String passPhrase) {
		String mnemonic = String.join(" ", mnemonicWords);
		byte [] seed = MnemonicUtils.generateSeed(mnemonic, passPhrase);
		byte [] privateKeyBytes = Hash.sha256(seed);
		ECKeyPair keyPair = ECKeyPair.create(privateKeyBytes);
		
		return Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
	}
	
	/**
	 * Returns the address for the provided private key  
	 * @param privateKey (hex string with prefix)
	 * @param passPhrase
	 */
	private String deriveAddressFromPrivateKey(String privateKey) {
		Credentials credentials = Credentials.create(privateKey);
		
		return credentials.getAddress();
	}
	
	@Override
	public JSONObject toJson(boolean includeProtocolInfo) {
		try {
			ECKeyPair keyPair = credentials.getEcKeyPair();
			WalletFile wallet = Wallet.createStandard(passPhrase, keyPair);
			JSONObject json = objectMapper.convertValue(wallet, JSONObject.class);
			return json;
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to convert wallet to json object", e);
		}
	}
}
