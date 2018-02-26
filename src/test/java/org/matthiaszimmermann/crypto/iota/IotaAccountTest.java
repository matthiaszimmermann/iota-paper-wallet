package org.matthiaszimmermann.crypto.iota;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.List;

import org.junit.Test;
import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.BaseTest;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;

public class IotaAccountTest extends BaseTest {

	@Test
	public void testCreateAccount() throws IOException {
		log("--- start testCreateAccount() ---");
		
		Protocol protocol = new Iota(Network.Production);
		List<String> mnemonicWords = protocol.generateMnemonicWords();
		Account account = ((Iota)protocol).restoreAccount(mnemonicWords, null);
		
		log("mnemonic words: '%s'", String.join(" ", mnemonicWords));
		log("seed: '%s'", account.getSecret());
		
		assertNotNull(account);
		
		log("account address: %s", account.getAddress());
		log("account json:"); 
		log(account.toJson().toString());
		log("account json pretty:");
		log(account.toJson("test pass phrase").toString(2));

		log("--- end testCreateAccount() ---");
	}
}