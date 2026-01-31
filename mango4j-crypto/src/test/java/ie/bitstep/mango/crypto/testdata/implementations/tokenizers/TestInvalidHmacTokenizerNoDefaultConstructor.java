package ie.bitstep.mango.crypto.testdata.implementations.tokenizers;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;

import java.util.List;

public class TestInvalidHmacTokenizerNoDefaultConstructor implements HmacTokenizer {

	public TestInvalidHmacTokenizerNoDefaultConstructor(String someParameter) {

	}

	@Override
	public List<HmacHolder> generateTokenizedValues(HmacHolder hmacHolder) {
		return List.of(new HmacHolder(hmacHolder.getCryptoKey(), hmacHolder.getValue()),
			new HmacHolder(hmacHolder.getCryptoKey(), hmacHolder.getValue()));
	}
}
