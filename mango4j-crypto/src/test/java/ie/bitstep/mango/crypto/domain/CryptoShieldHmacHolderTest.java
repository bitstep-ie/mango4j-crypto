package ie.bitstep.mango.crypto.domain;

import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import org.junit.jupiter.api.Test;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_IDENTITY_CRYPTO_KEY_ID;
import static org.assertj.core.api.Assertions.assertThat;

class CryptoShieldHmacHolderTest {

	private static final String TEST_DATA_TO_HMAC = "Test Data To HMAC";
	private static final String TEST_DATA_HMAC_ALIAS = "Test Data HMAC Alias";
	private static final String TEST_DATA_TOKENIZED_REPRESENTATION = "Test Data Tokenized Representation";

	@Test
	void constructorAllParams() {
		CryptoShieldHmacHolder hmacHolder = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder.getCryptoKeyId()).isEqualTo(TEST_IDENTITY_CRYPTO_KEY_ID);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isEqualTo(TEST_DATA_HMAC_ALIAS);
		assertThat(hmacHolder.getTokenizedRepresentation()).isEqualTo(TEST_DATA_TOKENIZED_REPRESENTATION);
	}

	@Test
	void constructorNoRepresentation() {
		CryptoShieldHmacHolder hmacHolder = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS);

		assertThat(hmacHolder.getCryptoKeyId()).isEqualTo(TEST_IDENTITY_CRYPTO_KEY_ID);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isEqualTo(TEST_DATA_HMAC_ALIAS);
	}

	@Test
	void constructorNoAlias() {
		CryptoShieldHmacHolder hmacHolder = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC);

		assertThat(hmacHolder.getCryptoKeyId()).isEqualTo(TEST_IDENTITY_CRYPTO_KEY_ID);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
		assertThat(hmacHolder.getHmacAlias()).isNull();
	}

	@Test
	void setters() {
		CryptoShieldHmacHolder hmacHolder = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, "Some other data");
		hmacHolder.setCryptoKeyId(TEST_CRYPTO_KEY_ID);
		hmacHolder.setValue(TEST_DATA_TO_HMAC);

		assertThat(hmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(hmacHolder.getValue()).isEqualTo(TEST_DATA_TO_HMAC);
	}

	@Test
	void hashCodeTest() {
		CryptoShieldHmacHolder hmacHolder = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder.hashCode()).isEqualTo(-225770549);
	}

	@SuppressWarnings("EqualsWithItself")
	@Test
	void equalsTestSameObject() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder1)).isTrue();
	}

	@Test
	void equalsWithDifferentObject() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(new Object())).isFalse();
	}

	@SuppressWarnings("ConstantValue")
	@Test
	void equalsNull() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(null)).isFalse();
	}

	@Test
	void equals() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		CryptoShieldHmacHolder hmacHolder2 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isTrue();
	}

	@Test
	void equalsDifferentCryptoKey() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		CryptoShieldHmacHolder hmacHolder2 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, "Some Other Alias", TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentAlias() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		CryptoShieldHmacHolder hmacHolder2 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, "Some Other Alias", TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentValues() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		CryptoShieldHmacHolder hmacHolder2 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, "Some other value", TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}

	@Test
	void equalsDifferentTokenizedRepresentations() {
		CryptoShieldHmacHolder hmacHolder1 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, TEST_DATA_TOKENIZED_REPRESENTATION);
		CryptoShieldHmacHolder hmacHolder2 = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_DATA_TO_HMAC, TEST_DATA_HMAC_ALIAS, "Some other tokenized representation");

		assertThat(hmacHolder1.equals(hmacHolder2)).isFalse();
	}
}