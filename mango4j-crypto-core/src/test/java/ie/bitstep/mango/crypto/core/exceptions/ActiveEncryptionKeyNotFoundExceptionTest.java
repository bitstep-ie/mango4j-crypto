package ie.bitstep.mango.crypto.core.exceptions;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ActiveEncryptionKeyNotFoundExceptionTest {

	@Test
	void constructorTest() {
		ActiveEncryptionKeyNotFoundException exception = new ActiveEncryptionKeyNotFoundException();
		assertThat(exception.getMessage()).isEqualTo("No active encryption key was found");
	}

}