package ie.bitstep.mango.crypto.tokenizers;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static org.assertj.core.api.Assertions.assertThat;

class PanTokenizerTest {

	private static final String UNDASHED_PAN = "1234567890123";
	private static final String PAN_PREFIX = "123456";
	private static final String PAN_SUFFIX = "0123";
	private static final String DASHED_PAN = "1234-5678-9012-3";
	private static final String DASHED_SHORT_PAN = "1234-5678-9012";
	private static final String SHORT_PAN = "123456789012";
	private static final String PAN_ALIAS = "pan";

	private final PanTokenizer panAnalyser = new PanTokenizer();

	private HmacHolder panHmacHolder;

	@BeforeEach
	void setup() {
		panHmacHolder = new HmacHolder(TEST_CRYPTO_KEY, DASHED_PAN, PAN_ALIAS);
	}

	@Test
	@DisplayName("Generate tokenized values for a PAN which contains dashes")
	void generateTokenizedValues() {
		List<HmacHolder> results = panAnalyser.generateTokenizedValues(panHmacHolder);

		assertThat(results).hasSize(3)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(PAN_SUFFIX)
				&& hmacHolder.getTokenizedRepresentation().equals("last4Digits"))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(PAN_PREFIX)
				&& hmacHolder.getTokenizedRepresentation().equals("first6Digits"))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(UNDASHED_PAN)
				&& hmacHolder.getTokenizedRepresentation().equals("normalizedPan"));
	}


	@Test
	@DisplayName("Generate tokenized values for a PAN which does not contain dashes")
	void generateTokenizedValuesNoDashes() {
		panHmacHolder.setValue(UNDASHED_PAN);

		List<HmacHolder> results = panAnalyser.generateTokenizedValues(panHmacHolder);

		assertThat(results).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(PAN_SUFFIX)
				&& hmacHolder.getTokenizedRepresentation().equals("last4Digits"))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(PAN_PREFIX)
				&& hmacHolder.getTokenizedRepresentation().equals("first6Digits"));
	}

	@Test
	@DisplayName("Generate tokenized values for a PAN which is too short, should only HMAC the original value")
	void generateTokenizedValuesTooShort() {
		panHmacHolder.setValue(DASHED_SHORT_PAN);

		List<HmacHolder> results = panAnalyser.generateTokenizedValues(panHmacHolder);

		assertThat(results).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY)
				&& hmacHolder.getHmacAlias().equals(PAN_ALIAS)
				&& hmacHolder.getValue().equals(SHORT_PAN)
				&& hmacHolder.getTokenizedRepresentation().equals("normalizedPan"))
			.hasSize(1);
	}
}