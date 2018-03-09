package org.matthiaszimmermann.crypto.ethereum;

import java.io.File;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;
import org.matthiaszimmermann.crypto.core.Wallet;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.WalletUtils;
import org.web3j.utils.Numeric;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EthereumWallet extends Wallet {

	private static final ObjectMapper objectMapper = new ObjectMapper();

	static {
		objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
		objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
	}

	private String privateKey = null;

	public EthereumWallet(File file, String passPhrase) throws Exception {
		super(file, passPhrase);
	}

	public EthereumWallet(List<String> mnemonicWords, String passPhrase, Network network) {
		this(mnemonicWords, passPhrase, ProtocolFactory.getInstance(Technology.Ethereum, network));

		privateKey = ((Ethereum) getProtocol()).derivePrivateKeyFromMnemonics(mnemonicWords, passPhrase);
	}

	@Override
	public String toString() {
		Credentials credentials = Credentials.create(privateKey);
		ECKeyPair keyPair = credentials.getEcKeyPair();
		String passPhrase = getPassPhrase();
		String walletString = null;
		
		// FIXME throws exception if passPhrase is null
		if(passPhrase == null) {
			passPhrase = "";
		}

		try {
			org.web3j.crypto.WalletFile wallet = org.web3j.crypto.Wallet.createStandard(passPhrase, keyPair);		
			walletString = objectMapper.writeValueAsString(wallet);
		}
		catch (Exception e) {
			throw new RuntimeException("Failed to convert wallet to string", e);
		}

		return walletString;
	}

	protected EthereumWallet(List<String> mnemonicWords, String passPhase, Protocol protocol) {
		super(mnemonicWords, passPhase, protocol);
	}

	@Override
	protected Account restore(File file, String passPhrase) throws Exception {
		if(!file.exists() || file.isDirectory()) { 
			throw new IllegalArgumentException(String.format("File '%s' does not exist or is a directory", file.getAbsolutePath()));
		}

		Credentials credentials = null;

		try {
			credentials = WalletUtils.loadCredentials(passPhrase, file);
		} 
		catch (Exception e) {
			throw new IllegalArgumentException(String.format("Failed to load credentials with provided password"));
		}
		
		ECKeyPair keyPair = credentials.getEcKeyPair();
		String secret = Numeric.toHexStringWithPrefix(keyPair.getPrivateKey());
		String address = credentials.getAddress();
		Network network = getProtocol().getNetwork();

		return new EthereumAccount(secret, address, network);
	}

	@Override
	public String getFileName() {
		String address = getAccount().getAddress();
		return getWalletFileName(stripLeading0x(address));
	}

	private String stripLeading0x(String address) {
		if(address != null && address.length() > 2) {
			if(address.startsWith("0x")) {
				return address.substring(2);
			}
		}
		
		return address;
	}

	// copied from web3j WalletUtils (function is private)
	private String getWalletFileName(String address) {
		DateTimeFormatter format = DateTimeFormatter.ofPattern(
				"'UTC--'yyyy-MM-dd'T'HH-mm-ss.nVV'--'");
		ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

		return now.format(format) + address + ".json";
	}

	@Override
	public String getSeed() {
		return privateKey;
	}
}
