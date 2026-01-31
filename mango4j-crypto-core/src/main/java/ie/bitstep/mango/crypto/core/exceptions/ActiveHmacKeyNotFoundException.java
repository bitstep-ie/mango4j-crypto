package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Exception thrown when this library unsuccessfully tries to get an active encryption key from the application's
 * {@link CryptoKeyProvider CryptoKeyProvider} implementation
 */
public class ActiveHmacKeyNotFoundException extends NonTransientCryptoException {
	/**
	 * Creates an exception when no active HMAC key is found.
	 */
	public ActiveHmacKeyNotFoundException() {
		super("No active HMAC key was found");
	}
}
