package ie.bitstep.mango.crypto.core.exceptions;

/**
 * Exception thrown if there was some problem trying to parse or format a ciphertext String
 */
public class CiphertextFormatterException extends NonTransientCryptoException {

	/**
	 * Creates an exception with a message.
	 *
	 * @param message the error message
	 */
	public CiphertextFormatterException(String message) {
		super(message);
	}

	/**
	 * Creates an exception with a message and cause.
	 *
	 * @param message the error message
	 * @param cause the underlying cause
	 */
	public CiphertextFormatterException(String message, Exception cause) {
		super(message, cause);
	}
}
