package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

public class NoHmacFieldsFoundException extends NonTransientCryptoException {
	/**
	 * Creates an exception when no HMAC fields are found.
	 *
	 * @param message the error message
	 */
	public NoHmacFieldsFoundException(String message) {
		super(message);
	}
}
