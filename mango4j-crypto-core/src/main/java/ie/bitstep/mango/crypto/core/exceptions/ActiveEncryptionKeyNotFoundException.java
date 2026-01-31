package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Exception thrown when this library unsuccessfully tries to get an active encryption key from the application's
 * {@link CryptoKeyProvider CryptoKeyProvider} implementation
 */
public class ActiveEncryptionKeyNotFoundException extends NonTransientCryptoException {
	/**
	 * Creates an exception when no active encryption key is found.
	 */
	public ActiveEncryptionKeyNotFoundException() {
		super("No active encryption key was found");
	}
}
