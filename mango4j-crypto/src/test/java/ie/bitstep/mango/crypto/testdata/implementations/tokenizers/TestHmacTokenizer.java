package ie.bitstep.mango.crypto.testdata.implementations.tokenizers;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;

import java.util.List;

public class TestHmacTokenizer implements HmacTokenizer {

	public static final String TOKENIZED_ALIAS_SUFFIX = "TOKENIZED_ALIAS_SUFFIX";
	public static final String TOKENIZED_VALUE_SUFFIX = "TOKENIZED_ALIAS_SUFFIX";

	@Override
	public List<HmacHolder> generateTokenizedValues(HmacHolder hmacHolder) {
		return List.of(
			new HmacHolder(hmacHolder.getCryptoKey(), hmacHolder.getValue() + TOKENIZED_VALUE_SUFFIX + 1,
				hmacHolder.getHmacAlias() + TOKENIZED_ALIAS_SUFFIX + 1),
			new HmacHolder(hmacHolder.getCryptoKey(), hmacHolder.getValue() + TOKENIZED_VALUE_SUFFIX + 2,
				hmacHolder.getHmacAlias() + TOKENIZED_ALIAS_SUFFIX + 2));
	}
}
