package org.matthiaszimmermann.crypto.core;

import java.io.File;
import java.util.List;

import org.json.JSONObject;
import org.matthiaszimmermann.crypto.utility.EntropyUtility;

public abstract class Protocol {

	private Technology technology;
	private Network network;

	public Protocol(Technology technology, Network network) {
		processTechnology(technology);
		processNetwork(network);
	}

	abstract public void validateMnemonicWords(List<String> mnemonicWords);

	abstract public Wallet createWallet(List<String> mnemonicWords, String passPhase);
	abstract public Wallet restoreWallet(File file, String passPhrase);

	abstract public Account createAccount(List<String> mnemonicWords, String passPhrase);
	abstract public Account restoreAccount(JSONObject accountJson, String passPhrase);

	public List<String> generateMnemonicWords() {
		byte [] entropy = EntropyUtility.generateEntropy();
		return Mnemonic.deriveWords(entropy);
	}

	private void processNetwork(Network n) {
		if(n == null) {
			throw new IllegalArgumentException("Network must not be null");
		}

		network = n;
	}

	private void processTechnology(Technology t) {
		if(t == null) {
			throw new IllegalArgumentException("Technology must not be null");
		}

		technology = t;
	}

	public Technology getTechnology() {
		return technology;
	}

	public Network getNetwork() {
		return network;
	}

	@Override
	public String toString() {
		return String.format("%s (%s)", getTechnology(), getNetwork());
	}

	@Override
	public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		}

		if(!(obj instanceof Protocol)) {
			return false;
		}

		Protocol other = (Protocol)obj;

		return technology == other.technology && network == other.network;
	}

	@Override
	public int hashCode() {
		return 1000 * technology.hashCode() + network.hashCode();
	}
}
