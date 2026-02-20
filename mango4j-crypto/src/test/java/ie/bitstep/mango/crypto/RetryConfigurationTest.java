package ie.bitstep.mango.crypto;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class RetryConfigurationTest {

	private static final Duration TEST_BACKOFF_DURATION = Duration.ofSeconds(4);
	private static final int TEST_MAX_ATTEMPTS = 3;
	private static final float TEST_BACK_OFF_MULTIPLIER = 3.666f;
	public static final int TEST_POOL_SIZE = 10;

	@Test
	void retryConfigurationPoolsizeLessThan1() {
		RetryConfiguration retryConfiguration = new RetryConfiguration(0, TEST_MAX_ATTEMPTS, TEST_BACKOFF_DURATION, TEST_BACK_OFF_MULTIPLIER);

		assertThat(retryConfiguration.maxAttempts()).isEqualTo(TEST_MAX_ATTEMPTS);
		assertThat(retryConfiguration.backoffDelay()).isEqualTo(TEST_BACKOFF_DURATION);
		assertThat(retryConfiguration.backOffMultiplier()).isEqualTo(3.7f);
		assertThat(retryConfiguration.poolSize()).isEqualTo(1);
	}

	@Test
	void retryConfigurationMultiplierRoundedToOneDecimalPlace() {
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, TEST_MAX_ATTEMPTS, TEST_BACKOFF_DURATION, TEST_BACK_OFF_MULTIPLIER);

		assertThat(retryConfiguration.maxAttempts()).isEqualTo(TEST_MAX_ATTEMPTS);
		assertThat(retryConfiguration.backoffDelay()).isEqualTo(TEST_BACKOFF_DURATION);
		assertThat(retryConfiguration.backOffMultiplier()).isEqualTo(3.7f);
	}

	@Test
	void retryConfigurationMaxAttemptsLessThan1() {
		assertThatThrownBy(() -> new RetryConfiguration(TEST_POOL_SIZE, 0, TEST_BACKOFF_DURATION, TEST_BACK_OFF_MULTIPLIER))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("maxAttempts (0) must be greater than 0");
	}

	@Test
	void retryConfigurationNullBackoffDelay() {
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, TEST_MAX_ATTEMPTS, null, TEST_BACK_OFF_MULTIPLIER);

		assertThat(retryConfiguration.maxAttempts()).isEqualTo(TEST_MAX_ATTEMPTS);
		assertThat(retryConfiguration.backoffDelay()).isEqualTo(Duration.ofMillis(100));
		assertThat(retryConfiguration.backOffMultiplier()).isEqualTo(3.7f);
	}

	@Test
	void retryConfigurationNegativeBackoffDelay() {
		Duration negativeBackoffDelay = Duration.ofSeconds(-2);
		assertThatThrownBy(() -> new RetryConfiguration(TEST_POOL_SIZE, TEST_MAX_ATTEMPTS, negativeBackoffDelay, TEST_BACK_OFF_MULTIPLIER))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("backoffDelay (PT-2S) must not be negative");
	}

	@Test
	void retryConfigurationBackoffMultiplierNegative() {
		assertThatThrownBy(() -> new RetryConfiguration(TEST_POOL_SIZE, TEST_MAX_ATTEMPTS, TEST_BACKOFF_DURATION, -1))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("backOffMultiplier (-1.0) cannot be negative");
	}

	@Test
	void retryConfigurationBackoffMultiplierZero() {
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, TEST_MAX_ATTEMPTS, TEST_BACKOFF_DURATION, 0);

		assertThat(retryConfiguration.poolSize()).isEqualTo(TEST_POOL_SIZE);
		assertThat(retryConfiguration.maxAttempts()).isEqualTo(TEST_MAX_ATTEMPTS);
		assertThat(retryConfiguration.backoffDelay()).isEqualTo(TEST_BACKOFF_DURATION);
		assertThat(retryConfiguration.backOffMultiplier()).isEqualTo(0.0f);
	}
}