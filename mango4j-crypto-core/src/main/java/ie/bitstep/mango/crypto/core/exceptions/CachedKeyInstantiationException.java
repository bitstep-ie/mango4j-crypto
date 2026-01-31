package ie.bitstep.mango.crypto.core.exceptions;

public class CachedKeyInstantiationException extends RuntimeException {
	/**
	 * Creates an exception for cache key instantiation failures.
	 *
	 * @param message the error message
	 */
	public CachedKeyInstantiationException(String message) {
		super(message);
	}
}
