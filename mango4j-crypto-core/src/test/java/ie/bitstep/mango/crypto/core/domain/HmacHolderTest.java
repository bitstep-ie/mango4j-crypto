package ie.bitstep.mango.crypto.core.domain;

import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class HmacHolderTest {

	private static final String TEST_DATA_TO_HMAC = "Test Data To HMAC";
	private static final String TEST_DATA_HMAC_ALIAS = "Test Data HMAC Alias";
	private static final String TEST_DATA_TOKENIZED_REPRESENTATION = "Test Data Tokenized Representation";

	@Test
	void constructorAllParams() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isEqualTo(TEST_DATA_HMAC_ALIAS);
		assertThat(hmacHolder.getTokenizedRepresentation()).isEqualTo(TEST_DATA_TOKENIZED_REPRESENTATION);
	}

	@Test
	void constructorNoRepresentation() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS);

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isEqualTo(TEST_DATA_HMAC_ALIAS);
	}

	@Test
	void constructorNoAlias() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC);

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isNull();
	}

	@Test
	void setters() {
		HmacHolder hmacHolder = new HmacHolder(new CryptoKey(), "Some other data");
		hmacHolder.setCryptoKey(TestData.TEST_BASE_64_CRYPTO_KEY);
		hmacHolder.setValue(TEST_DATA_TO_HMAC);

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
	}

	@Test
	void hashCodeTest() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder.hashCode()).isEqualTo(-1949446445);
	}

	@SuppressWarnings("EqualsWithItself")
	@Test
	void equalsTestSameObject() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder1)).isTrue();
	}

	@Test
	void equalsWithDifferentObject() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(new Object())).isFalse();
	}

	@SuppressWarnings("ConstantValue")
	@Test
	void equalsNull() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(null)).isFalse();
	}

	@Test
	void equals() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		HmacHolder hmacHolder2 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isTrue();
	}

	@Test
	void equalsDifferentCryptoKey() {
		HmacHolder hmacHolder1 = new HmacHolder(new CryptoKey(), TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		HmacHolder hmacHolder2 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, "Some Other Alias", TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentAlias() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		HmacHolder hmacHolder2 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, "Some Other Alias", TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentValues() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		HmacHolder hmacHolder2 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, "Some other value", TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentTokenizedRepresentations() {
		HmacHolder hmacHolder1 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		HmacHolder hmacHolder2 = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, "Some other tokenized representation");

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}
}