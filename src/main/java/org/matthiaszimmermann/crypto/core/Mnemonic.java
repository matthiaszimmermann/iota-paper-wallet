package org.matthiaszimmermann.crypto.core;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException.MnemonicChecksumException;
import org.bitcoinj.crypto.MnemonicException.MnemonicLengthException;
import org.bitcoinj.crypto.MnemonicException.MnemonicWordException;

/**
 */
public class Mnemonic {
	
	/**
	 * Converts entropy data to mnemonic word list.
	 * Implementation depends on bitcoinj library.
	 */
	public static List<String> deriveWords(byte [] entropy) {
		try {
			MnemonicCode mc = new MnemonicCode();
			List<String> words = mc.toMnemonic(entropy);
			return words;
		} 
		catch (Exception e) {
			throw new RuntimeException("Failed to derive mnemonic words from entropy", e);
		}
	}
	
	/**
	 * Converts mnemonic word list to corresponding entropy data.
	 * Implementation depends on bitcoinj library.
	 */
	public static byte [] deriveEntropy(List<String> mnemonicWords) throws IOException, MnemonicLengthException, MnemonicWordException, MnemonicChecksumException {
		try {
		MnemonicCode mc = new MnemonicCode();
		byte [] entropy = mc.toEntropy(mnemonicWords);
		return entropy;
		} 
		catch (Exception e) {
			throw new RuntimeException("Failed to derive entropy from mnemonic words", e);
		}
	}
	
	/**
	 * Concatenates words to a space separated string.
	 */
	public static String convert(List<String> words) {
		return words == null ? "" : String.join(" ", words);
	}
	
	/**
	 * Separates a sentence of space separated words into a list of its individual words.
	 */
	public static List<String> convert(String sentence) {
		return Arrays.asList(sentence.split(" "));
	}
}
