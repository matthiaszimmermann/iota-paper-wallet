package org.matthiaszimmermann.crypto.common;

public enum Network {
	Production,
	Test,
	Local;
	
	public static Network get(String name) {
		if(name == null || name.length() == 0) {
			throw new IllegalArgumentException("Provided name must not be null or empty");
		}
		
		String query = name.toLowerCase();
		
		if(Production.name().toLowerCase().equals(query)) {
			return Production;
		}
		else if(Test.name().toLowerCase().equals(query)) {
			return Test;
		}
		else if(Local.name().toLowerCase().equals(query)) {
			return Local;
		}
		else {
			throw new IllegalArgumentException("Unknown network:" + name);
		}
	}
}
