package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ActiveHmacKeyNotFoundExceptionTest {

	@Test
	void activeCryptoKeyNotFoundExceptionNewInstance() {
		ActiveHmacKeyNotFoundException activeHmacKeyNotFoundException = new ActiveHmacKeyNotFoundException();

		assertThat(activeHmacKeyNotFoundException.getMessage()).isEqualTo("No active HMAC key was found");
	}
}