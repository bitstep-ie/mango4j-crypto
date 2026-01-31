package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.tokenizers.PanTokenizer;
import ie.bitstep.mango.crypto.exceptions.HmacTokenizerInstantiationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HmacTokenizerInstantiationExceptionTest {

	@Test
	void hmacTokenizerInstantiationExceptionNewInstance() {
		HmacTokenizerInstantiationException HmacTokenizerInstantiationException = new HmacTokenizerInstantiationException(PanTokenizer.class);

		assertThat(HmacTokenizerInstantiationException.getMessage())
			.isEqualTo("Could not create an instance of HmacTokenizer type PanTokenizer. " +
				"Please make sure that PanTokenizer has a default no-args constructor declared");
	}
}