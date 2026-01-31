package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.CiphertextFormatterException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CiphertextFormatterExceptionTest {

	@Test
	void messageConstructor() {
		CiphertextFormatterException exception = new CiphertextFormatterException("message");

		assertThat(exception.getMessage()).isEqualTo("message");
	}

	@Test
	void messageAndCauseConstructor() {
		Exception cause = new Exception();

		CiphertextFormatterException exception = new CiphertextFormatterException("message", cause);

		assertThat(exception.getMessage()).isEqualTo("message");
		assertThat(exception.getCause()).isEqualTo(cause);
	}

}