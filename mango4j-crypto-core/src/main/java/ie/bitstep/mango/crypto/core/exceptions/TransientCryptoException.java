package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;

/**
 * Exception that might be thrown by cryptographic operation methods in
 * {@link EncryptionServiceDelegate EncryptionServiceDelegates}
 * for some operation that may be retried.
 */
public class TransientCryptoException extends RuntimeException {

	/**
	 * Creates an exception with a message and cause.
	 *
	 * @param message the error message
	 * @param cause the underlying cause
	 */
	public TransientCryptoException(String message, Throwable cause) {
		super(message, cause);
	}
}
