package ie.bitstep.mango.crypto.testdata;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.time.Duration;
import java.time.Instant;

public class TestData {

	public static final String MOCK_TEST_KEY_TYPE = "MockTestKey";
	public static final String TEST_CRYPTO_KEY_ID = "TestCryptoKeyId";
	public static final CryptoKey TEST_CRYPTO_KEY;

	public static final String TEST_NEW_CRYPTO_KEY_TYPE = "Test CryptoKeyType";
	public static final String TEST_IDENTITY_CRYPTO_KEY_ID = "Test Identity Crypto Key ID";

	static {
		TEST_CRYPTO_KEY = new CryptoKey();
		TEST_CRYPTO_KEY.setId(TEST_CRYPTO_KEY_ID);
		TEST_CRYPTO_KEY.setType(MOCK_TEST_KEY_TYPE);
	}

	public static final String TEST_PAN = "5454545454545454";
	public static final String PAN_FIELD_NAME = "pan";
	public static final String TEST_MOCK_SOURCE_CIPHERTEXT = "{\"" + PAN_FIELD_NAME + "\": \"" + TEST_PAN + "\"}";

	public static CryptoKey testCryptoKey() {
		CryptoKey testCryptoKey = new CryptoKey();
		testCryptoKey.setId(TEST_CRYPTO_KEY_ID);
		testCryptoKey.setType(MOCK_TEST_KEY_TYPE);
		testCryptoKey.setKeyStartTime(Instant.now().minus(Duration.ofDays(1)));
		testCryptoKey.setCreatedDate(Instant.now());
		return testCryptoKey;
	}
}

