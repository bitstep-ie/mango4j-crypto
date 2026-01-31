package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;

/**
 * Exception that might be thrown by cryptographic operation methods in
 * {@link EncryptionServiceDelegate EncryptionServiceDelegates}
 * for some operation that <u>should <b><i>not</i></b> be retried</u>.
 */
public class NonTransientCryptoException extends RuntimeException {

	/**
	 * Creates an exception with a message and cause.
	 *
	 * @param message the error message
	 * @param cause the underlying cause
	 */
	public NonTransientCryptoException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Creates an exception with a message.
	 *
	 * @param message the error message
	 */
	public NonTransientCryptoException(String message) {
		super(message);
	}
}
