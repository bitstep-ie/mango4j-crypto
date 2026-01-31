package ie.bitstep.mango.crypto.keyrotation.exceptions;

public class TooManyFailuresException extends RuntimeException {

	/**
	 * Creates an exception when the failure threshold is exceeded.
	 *
	 * @param message the error message
	 */
	public TooManyFailuresException(String message) {
		super(message);
	}
}
