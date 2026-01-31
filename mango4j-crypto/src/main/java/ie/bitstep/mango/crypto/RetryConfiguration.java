package ie.bitstep.mango.crypto;

import java.time.Duration;

import static java.lang.Math.round;
import static java.lang.String.format;

/**
 * Configuration for retrying transient crypto operations.
 *
 * @param poolSize         number of threads for retry execution
 * @param maxAttempts      maximum retry attempts before failing
 * @param backoffDelay     base backoff delay between attempts
 * @param backOffMultiplier multiplier applied to successive backoff delays
 */
public record RetryConfiguration(int poolSize, int maxAttempts, Duration backoffDelay, float backOffMultiplier) {

	public static final Duration DEFAULT_BACKOFF_DELAY = Duration.ofMillis(100);

	/**
	 * Validates and normalizes retry configuration values.
	 */
	public RetryConfiguration {
		if (poolSize < 1) {
			poolSize = 1;
		}

		if (maxAttempts < 1) {
			throw new IllegalArgumentException(format("maxAttempts (%s) must be greater than 0", maxAttempts));
		}

		if (backoffDelay == null) {
			backoffDelay = DEFAULT_BACKOFF_DELAY;
		} else if (backoffDelay.isNegative()) {
			throw new IllegalArgumentException(format("backoffDelay (%s) must not be negative", backoffDelay));
		}

		if (backOffMultiplier < 0) {
			throw new IllegalArgumentException(format("backOffMultiplier (%s) cannot be negative", backOffMultiplier));
		} else if (backOffMultiplier > 0) {
			backOffMultiplier = round(backOffMultiplier * 10) / 10.0f; // round to one decimal place
		}
	}
}
