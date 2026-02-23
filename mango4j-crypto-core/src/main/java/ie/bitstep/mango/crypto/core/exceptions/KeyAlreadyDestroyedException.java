package ie.bitstep.mango.crypto.core.exceptions;

/**
 * Thrown when a key destruction request is repeated for an already-destroyed key.
 */
public class KeyAlreadyDestroyedException extends RuntimeException {
	/**
	 * Creates a new exception with no detail message.
	 */
	public KeyAlreadyDestroyedException() {
		// No need for any other information for security reasons - we don't want to leak any information about the key or its state
	}
}