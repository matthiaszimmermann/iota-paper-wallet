package org.matthiaszimmermann.crypto.bitcoin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.List;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Mnemonic;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;
import org.matthiaszimmermann.crypto.core.ProtocolFactory;
import org.matthiaszimmermann.crypto.core.Technology;

public class BitcoinAccountTest extends BaseTest {
	
	public static final String MNEMONIC_WORDS_FIXED = "history suit seat regular toe valid circle public issue degree river vendor";
	public static final String SECRET_FIXED = "history suit seat regular toe valid circle public issue degree river vendor";
	public static final String ADDRESS_FIXED = "18RJUfZwBTaNSNS55seBRzkMSvLkvjKtur";
	public static final String PASS_PHRASE = "test_pass_phrase";

	@Test
	public void verifyMatchingAddress() throws IOException, JSONException {
		Network network = Network.Production;
		Protocol protocol = ProtocolFactory.getInstance(Technology.Bitcoin, network);
		List<String> mnemonicWords = Mnemonic.convert(MNEMONIC_WORDS_FIXED);
		
		Account account = protocol.createAccount(mnemonicWords, PASS_PHRASE, network);
		String secret = account.deriveSecret(mnemonicWords, PASS_PHRASE);
		String address = account.deriveAddress(secret, network);
		
		assertNotNull(account);
		assertNotNull(secret);
		assertNotNull(address);

		assertEquals("Secret mismatch", SECRET_FIXED, secret);
		assertEquals("Address mismatch", ADDRESS_FIXED, address);
		
		assertEquals(secret, account.getSecret());
		assertEquals(address, account.getAddress());
	}
	
	@Test
	public void testCreateAndRestore() throws IOException, JSONException {
		Network network = Network.Production;
		Protocol protocol = ProtocolFactory.getInstance(Technology.Bitcoin, network);
		List<String> mnemonicWords = protocol.generateMnemonicWords();
		Account accountNew = protocol.createAccount(mnemonicWords, PASS_PHRASE, network);

		assertNotNull(accountNew);
		
		JSONObject json = accountNew.toJson(false);
		Account accountRestored = protocol.restoreAccount(json, PASS_PHRASE);
		
		assertEquals(accountNew, accountRestored);
	}

	@Test
	public void testCreateAccount() throws IOException {
		log("--- start testCreateAccount() ---");
		
		Protocol protocol = new Bitcoin(Network.Production);
		List<String> mnemonicWords = protocol.generateMnemonicWords();
		Account account = new BitcoinAccount(mnemonicWords, PASS_PHRASE, protocol.getNetwork());
		
		log("mnemonic words (bip39 seed): '%s'", String.join(" ", mnemonicWords));
		
		assertNotNull(account);
		
		log("account address: %s", account.getAddress());
		
		try {
			log("account json:"); 
			log(account.toJson().toString());
			
			log("account json pretty:");
			log(account.toJson(true).toString(2));
		} 
		catch (JSONException e) {
			e.printStackTrace();
		}

		log("--- end testCreateAccount() ---");
	}
}