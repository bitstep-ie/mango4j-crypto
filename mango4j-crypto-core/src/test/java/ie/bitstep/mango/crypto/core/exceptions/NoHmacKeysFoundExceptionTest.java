package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NoHmacKeysFoundException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class NoHmacKeysFoundExceptionTest {

	@Test
	void noHmacKeysFoundExceptionNewInstance() {
		NoHmacKeysFoundException noHmacKeysFoundException = new NoHmacKeysFoundException();

		assertThat(noHmacKeysFoundException.getMessage()).isEqualTo("No HMAC CryptoKeys were found");
	}
}