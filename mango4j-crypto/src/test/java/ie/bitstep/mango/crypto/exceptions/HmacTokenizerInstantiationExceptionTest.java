package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.tokenizers.PanTokenizer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HmacTokenizerInstantiationExceptionTest {

	@Test
	void hmacTokenizerInstantiationExceptionNewInstance() {
		HmacTokenizerInstantiationException hmacTokenizerInstantiationException = new HmacTokenizerInstantiationException(PanTokenizer.class);

		assertThat(hmacTokenizerInstantiationException.getMessage())
			.isEqualTo("Could not create an instance of HmacTokenizer type PanTokenizer. " +
				"Please make sure that PanTokenizer has a default no-args constructor declared");
	}
}