package ie.bitstep.mango.crypto.core.testdata;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.util.Map;

public class TestData {

	public static final String TEST_CRYPTO_KEY_ID = "Test Crypto Key ID";
	public static final String TEST_CRYPTO_KEY_TYPE = "MockCryptoKeyType";
	public static final CryptoKeyUsage TEST_CRYPTO_KEY_USAGE = CryptoKeyUsage.ENCRYPTION;
	public static final CryptoKey TEST_BASE_64_CRYPTO_KEY = new CryptoKey();
	public static final String TEST_SOURCE_CLEAR_TEXT = "MockSourceValue";
	public static final String TEST_FINAL_CIPHERTEXT = "TEST CIPHERTEXT";
	public static final String TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME = "data";

	public static CryptoKey testCryptoKey() {
		CryptoKey testMockCryptoKey = new CryptoKey();
		testMockCryptoKey.setId(TEST_CRYPTO_KEY_ID);
		testMockCryptoKey.setType(TEST_CRYPTO_KEY_TYPE);
		testMockCryptoKey.setUsage(TEST_CRYPTO_KEY_USAGE);
		return testMockCryptoKey;
	}

	public static CiphertextContainer testCipherTextContainer() {
		return new CiphertextContainer(testCryptoKey(), Map.of(TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME, TEST_SOURCE_CLEAR_TEXT));
	}

	public static HmacHolder testHmacHolder() {
		return new HmacHolder(testCryptoKey(), TEST_SOURCE_CLEAR_TEXT);
	}
}
