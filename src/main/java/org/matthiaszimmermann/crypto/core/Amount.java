package org.matthiaszimmermann.crypto.core;

import java.math.BigInteger;

public class Amount {

	private BigInteger value;
	private CurrencyUnit unit;
	
	public Amount(long value, CurrencyUnit unit) {
		this(BigInteger.valueOf(value), unit);
	}
	
	public Amount(BigInteger value, CurrencyUnit unit) {
		
		if(value == null) {
			throw new IllegalArgumentException("Value must not be null");
		}
		
		if(unit == null) {
			throw new IllegalArgumentException("Unit must not be null");
		}
		
		this.value = value;
		this.unit = unit;
	}
	
	public BigInteger getValue() {
		return value;
	}
	
	public CurrencyUnit getUnit() {
		return unit;
	}
}
