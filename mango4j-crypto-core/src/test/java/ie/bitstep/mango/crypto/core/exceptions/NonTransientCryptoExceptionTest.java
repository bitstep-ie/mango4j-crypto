package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NonTransientCryptoExceptionTest {

	@Test
	void messageAndCauseConstructor() {
		RuntimeException testCause = new RuntimeException();
		String testMessage = "Test Message";

		NonTransientCryptoException nonTransientCryptoException = new NonTransientCryptoException(testMessage, testCause);

		assertThat(nonTransientCryptoException.getMessage()).isEqualTo(testMessage);
		assertThat(nonTransientCryptoException.getCause()).isEqualTo(testCause);
	}

	@Test
	void messageConstructor() {
		String testMessage = "Test Message";

		NonTransientCryptoException nonTransientCryptoException = new NonTransientCryptoException(testMessage);

		assertThat(nonTransientCryptoException.getMessage()).isEqualTo(testMessage);
	}
}