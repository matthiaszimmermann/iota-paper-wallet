package org.matthiaszimmermann.crypto.pwg.iota;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import org.matthiaszimmermann.crypto.common.Mnemonic;

import jota.error.ArgumentException;
import jota.pow.ICurl;
import jota.pow.JCurl;
import jota.pow.SpongeFactory;
import jota.utils.IotaAPIUtils;

/**
 * @author matthiaszimmermann
 */
public class Application {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, ArgumentException {
    	String passPhrase= "pass phrase";
		Mnemonic m = new Mnemonic();
		byte [] entropy = m.generateEntropy();
		
		List<String> words = m.toMnemonic(entropy);
		System.out.println("mnemonic string: " + String.join(" ", words));
		
		String seed = Mnemonic.toIotaSeed(words, passPhrase);
		System.out.println("iota seed: " + seed);
		
		int securityLevel = 2;
		int index = 0;
		boolean checksum = true;
		ICurl curl = new JCurl(SpongeFactory.Mode.CURLP81);
		String address = IotaAPIUtils.newAddress(seed, securityLevel, index, checksum, curl);
		System.out.println("address[" + index + "] security level " + securityLevel + ": " + address);
		
		String sentence = "thank essence during frequent frost area pizza senior message jump course cliff";
		List<String> wordsFromSentence = Arrays.asList(sentence.split(" "));
		String seedFromWords = m.toIotaSeed(wordsFromSentence, passPhrase);
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
    }
}