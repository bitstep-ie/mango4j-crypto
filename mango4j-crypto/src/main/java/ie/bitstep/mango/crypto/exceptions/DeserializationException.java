package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

public class DeserializationException extends NonTransientCryptoException {
	/**
	 * Creates an exception for deserialization failures.
	 *
	 * @param message the error message
	 */
	public DeserializationException(String message) {
		super(message);
	}
}
