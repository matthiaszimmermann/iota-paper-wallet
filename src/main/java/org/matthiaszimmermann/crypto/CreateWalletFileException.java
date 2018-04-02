package org.matthiaszimmermann.crypto;

public class CreateWalletFileException extends RuntimeException {
	
	private static final long serialVersionUID = 1L;

	public CreateWalletFileException() {
    }

    public CreateWalletFileException(String message) {
        super(message);
    }
}
