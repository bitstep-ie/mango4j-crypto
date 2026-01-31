package ie.bitstep.mango.crypto.core.exceptions;

/**
 * Thrown when a key destruction request is repeated for an already-destroyed key.
 */
public class KeyAlreadyDestroyedException extends RuntimeException {
	/**
	 * Creates a new exception with no detail message.
	 */
	public KeyAlreadyDestroyedException() {
	}
}
