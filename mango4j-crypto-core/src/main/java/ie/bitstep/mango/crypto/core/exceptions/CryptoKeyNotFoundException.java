package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Exception thrown when this library unsuccessfully tries to get a key from the application's
 * {@link CryptoKeyProvider CryptoKeyProvider} implementation
 */
public class CryptoKeyNotFoundException extends NonTransientCryptoException {
	/**
	 * Creates an exception for a missing crypto key.
	 *
	 * @param cryptoKeyId the missing key ID
	 */
	public CryptoKeyNotFoundException(String cryptoKeyId) {
		super(String.format("Crypto Key with ID '%s' not found", cryptoKeyId));
	}
}
