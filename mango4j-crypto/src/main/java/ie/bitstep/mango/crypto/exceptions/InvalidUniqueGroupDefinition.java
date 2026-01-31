package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

public class InvalidUniqueGroupDefinition extends NonTransientCryptoException {
	/**
	 * Creates an exception for invalid unique group definitions.
	 *
	 * @param message the error message
	 */
	public InvalidUniqueGroupDefinition(String message) {
		super(message);
	}
}
