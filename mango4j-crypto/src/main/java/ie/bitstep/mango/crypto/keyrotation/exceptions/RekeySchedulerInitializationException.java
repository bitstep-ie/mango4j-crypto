package ie.bitstep.mango.crypto.keyrotation.exceptions;

public class RekeySchedulerInitializationException extends RuntimeException {
	/**
	 * Creates an exception for scheduler initialization failures.
	 */
	public RekeySchedulerInitializationException() {
		// initialization errors are logged individually and this is only thrown in 1 place
	}
}
