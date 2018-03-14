package org.matthiaszimmermann.crypto.bitcoin;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.List;

import org.json.JSONException;
import org.junit.Test;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.core.Account;
import org.matthiaszimmermann.crypto.core.Network;
import org.matthiaszimmermann.crypto.core.Protocol;

public class BitcoinAccountTest extends BaseTest {

	@Test
	public void testCreateAccount() throws IOException {
		log("--- start testCreateAccount() ---");
		
		Protocol protocol = new Bitcoin(Network.Production);
		List<String> mnemonicWords = protocol.generateMnemonicWords();
		String passPhrase = "pass phrase";
		Account account = new BitcoinAccount(mnemonicWords, passPhrase, protocol.getNetwork());
		
		log("mnemonic words (bip39 seed): '%s'", String.join(" ", mnemonicWords));
		
		assertNotNull(account);
		
		log("account address: %s", account.getAddress());
		
		try {
			log("account json:"); 
			log(account.toJson().toString());
			
			log("account json pretty:");
			log(account.toJson(passPhrase, true).toString(2));
		} 
		catch (JSONException e) {
			e.printStackTrace();
		}
		
		// assertTrue(string.length() > 0);
		// assertEquals("dfgh", string);

		log("--- end testCreateAccount() ---");
	}
}