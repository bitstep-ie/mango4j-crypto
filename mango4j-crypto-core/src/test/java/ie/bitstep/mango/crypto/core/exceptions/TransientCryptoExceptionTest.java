package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.TransientCryptoException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TransientCryptoExceptionTest {

	@Test
	void transientCryptoExceptionNewInstance() {
		RuntimeException testCause = new RuntimeException();
		String testMessage = "Test Message";

		TransientCryptoException transientCryptoException = new TransientCryptoException(testMessage, testCause);

		assertThat(transientCryptoException.getMessage()).isEqualTo(testMessage);
		assertThat(transientCryptoException.getCause()).isEqualTo(testCause);
	}
}