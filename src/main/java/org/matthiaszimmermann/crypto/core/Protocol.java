package org.matthiaszimmermann.crypto.core;

import java.util.List;

public abstract class Protocol {
	
	private Technology technology;
	private Network network;
	
	public Protocol(Technology technology, Network network) {
		processTechnology(technology);
		processNetwork(network);
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
	
	abstract public Account restoreAccount(List<String> mnemonicWords, String passPhrase);

	abstract public List<String> generateMnemonicWords();

	abstract public void validateMnemonicWords(List<String> mnemonicWords);
	
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
