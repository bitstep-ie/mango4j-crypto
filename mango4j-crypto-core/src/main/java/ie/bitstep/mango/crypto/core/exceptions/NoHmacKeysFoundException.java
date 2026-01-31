package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Exception thrown when this library unsuccessfully tries to get the list of current HMAC keys from the application's
 * {@link CryptoKeyProvider CryptoKeyProvider} implementation
 */
public class NoHmacKeysFoundException extends NonTransientCryptoException {
	/**
	 * Creates an exception when no HMAC keys are available.
	 */
	public NoHmacKeysFoundException() {
		super("No HMAC CryptoKeys were found");
	}
}
