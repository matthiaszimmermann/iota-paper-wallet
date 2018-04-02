package org.matthiaszimmermann.crypto;

public class VerifyWalletFileException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;

	public VerifyWalletFileException() {
    }

    public VerifyWalletFileException(String message) {
        super(message);
    }
}
