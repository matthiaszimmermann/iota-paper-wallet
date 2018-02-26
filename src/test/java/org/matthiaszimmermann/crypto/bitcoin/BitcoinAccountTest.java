package org.matthiaszimmermann.crypto.bitcoin;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.List;

import org.junit.Test;
import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;

public class BitcoinAccountTest extends BaseTest {

	@Test
	public void testCreateAccount() throws IOException {
		log("--- start testCreateAccount() ---");
		
		Protocol protocol = new Bitcoin(Network.Production);
		List<String> mnemonicWords = protocol.generateMnemonicWords();
		Account account = new BitcoinAccount(mnemonicWords, protocol.getNetwork());
		
		log("mnemonic words (bip39 seed): '%s'", String.join(" ", mnemonicWords));
		
		assertNotNull(account);
		
		log("account address: %s", account.getAddress());
		log("account json:"); 
		log(account.toJson().toString());
		log("account json pretty:");
		log(account.toJson("pass phrase").toString(2));
		
		// assertTrue(string.length() > 0);
		// assertEquals("dfgh", string);

		log("--- end testCreateAccount() ---");
	}
}