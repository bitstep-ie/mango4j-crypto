package ie.bitstep.mango.crypto.exceptions;


import ie.bitstep.mango.crypto.exceptions.DeserializationException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class DeserializationExceptionTest {

	@ParameterizedTest
	@ValueSource(strings = {"test", ""})
	void constructorTest(String message) {
		DeserializationException exception = new DeserializationException(message);
		assertThat(exception.getMessage()).isEqualTo(message);
	}

}