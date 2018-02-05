package org.matthiaszimmermann.crypto.pwg.iota;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.util.Arrays;
import org.matthiaszimmermann.crypto.common.Account;
import org.matthiaszimmermann.crypto.common.AesUtility;
import org.matthiaszimmermann.crypto.common.Entropy;
import org.matthiaszimmermann.crypto.common.Mnemonic;
import org.matthiaszimmermann.crypto.common.Network;
import org.matthiaszimmermann.crypto.common.Protocol;
import org.matthiaszimmermann.crypto.common.ProtocolFactory;
import org.matthiaszimmermann.crypto.common.Seed;
import org.matthiaszimmermann.crypto.common.Technology;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

/**
 * projectname ?
 * 
 * Entropy: *-> byte array that encodes entropy
 * Mnemonic: entropy -> word list -> entropy
 * Account: word list -> account
 * - (private) key/seed (the secret that provides access to funds stored under the address)
 * - (public) address
 * Currency Units (iota/?, ether/wei, bitcoin/satoshi, ...)
 * Amount
 * - Currency Unit
 * - Number (BigDecimal)
 * Transaction
 *   - status
 *   - hash (is there a iota tx hash?)
 *   - Sender (account)
 *   - Recipient (address)
 *   - Amount
 *   OfflineTransaction
 *     SignedOfflineTransaction (how is this done in iota?)
 * 
 * Protocol Implementation
 *   Bitcoin
 *   Ethereum
 *   Iota
 *   
 *   Protocol p = xy.new();
 *   Account a = p.restoreAccount(words, wordlist) // what about passphrase?
 *   String recipientAddress = "xyz";
 *   Amount amount = p.getAmount(0.01, CurrencyUnit.Bitcoin);
 *   Transaction tx = p.createTransaction(Account, recipientAddress, amount);
 *   
 *   p.connect();
 *   String txHash = p.submit(tx);
 *   
 *   Entropy.generate(int bits)
 *   Mnemonic.loadWordList()
 *   Mnemonic.toWords(byte [] entropy, List<String> wordList)
 *   Protocol.restoreAccount(List<String> words, List<String> wordList)
 *   Protocol.createTransaction(Account sender, String recipient, Amount amount)
 *   Protocol.connect()
 *   Protocol.submit(Transaction transaction) // what about tx fees?
 *   Protocol.getBalance(Account account)
 *   
 * 
 * @author matthiaszimmermann
 */
public class DummyApplication {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, ArgumentException {
		String passPhrase= "pass phrase";
		
		byte [] entropy = Entropy.generateEntropy();
		List<String> wordList = Mnemonic.loadWordList();
		List<String> words = Mnemonic.toWords(entropy, wordList);
		String seed = Seed.toIotaSeed(words, passPhrase);

		System.out.println("mnemonic string: " + Mnemonic.convert(words));
		System.out.println("iota seed: " + seed);
		
		byte [] entropyFromWords = Mnemonic.toEntropy(words, wordList);
		
		if(!Arrays.areEqual(entropy, entropyFromWords)) {
			System.err.println("entropy mismatch");
		}
		else {
			System.out.println("entropy ("+ (8 * entropy.length) + " bits) successfully recreated from words");
		}

		int securityLevel = 2;
		int index = 0;
		boolean checksum = true;
		ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
		String address = IotaAPIUtils.newAddress(seed, securityLevel, index, checksum, curl);
		System.out.println("address[" + index + "] security level " + securityLevel + ": " + address);

		String sentence = "thank essence during frequent frost area pizza senior message jump course cliff";
		List<String> wordsFromSentence = Mnemonic.convert(sentence);
		String seedFromWords = Seed.toIotaSeed(wordsFromSentence, passPhrase);
		String addressFromSeed = IotaAPIUtils.newAddress(seedFromWords, securityLevel, index, checksum, curl);

		String expectedSeed = "KEFTZOPPKPBPXOJPRYNLKQNJQIPNCCDZPFASRGHNXDOOVFVFUFZHSYGPDAGPHMUWFRFYGEBXOFJTIBFVG";
		if(seedFromWords.equals(expectedSeed)) {
			System.out.println("sentence: " + sentence);
			System.out.println("expected iota seed: " + seedFromWords);
		}
		else {
			System.err.println("seed mismatch\nexpected: " + expectedSeed + "\nactual: " + seedFromWords);
		}

		String expectedAddress = "WBWMGJYFWMCFILCSGGKWOXSQBJFCYSEFLBY9ZBAMYPCYSDNYMJPNF9BHYJJERUNITYCMFUQCRNUYKYEOACNFEUFD9D";
		if(addressFromSeed.equals(expectedAddress)) {
			System.out.println("expected iota address: " + addressFromSeed);
		}
		else {
			System.err.println("address mismatch\nexpected: " + expectedAddress + "\nactual: " + addressFromSeed);
		}
		
		System.out.println("------------------------------");
		Protocol iota = ProtocolFactory.getInstance(Technology.Iota, Network.Production);
		Account account = iota.restoreAccount(wordsFromSentence, passPhrase);
		
		System.out.println("API mnemonic words:   " + Mnemonic.convert(wordsFromSentence));
		System.out.println("API pass phrase:      " + passPhrase);
		System.out.println("API seed expected:    " + expectedSeed);
		System.out.println("API seed actual:      " + account.getSecret() + " match=" + expectedSeed.equals(account.getSecret()));
		
		System.out.println("API address expected: " + expectedAddress);
		System.out.println("API address actual:   " + account.getAddress() + " match=" + expectedAddress.equals(account.getAddress()));
		System.out.println("------------------------------");
		
		try {
			AesUtility aes = new AesUtility(passPhrase);
			String seedEncrypted = aes.encrypt(expectedSeed);
			String iv = aes.getIv();
			AesUtility aes2 = new AesUtility(passPhrase);
			String seedDecrypted = aes2.decrypt(seedEncrypted, iv);
			
			System.out.println("API seed encrypted:    " + seedEncrypted);
			System.out.println("API seed decrypted:    " + seedDecrypted + " match=" + expectedSeed.equals(seedDecrypted));
			System.out.println("------------------------------");
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			TimeUnit.MILLISECONDS.sleep(10);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		String testSentence = sentence + " " + "neuesWort nochEins undDasLetzte";
		Mnemonic.check(wordList, Mnemonic.convert(testSentence));
	}
}