package ie.bitstep.mango.crypto.core.testdata;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.PBKDF2EncryptionService;

import java.util.Map;

public class TestData {

	public static final String TEST_CRYPTO_KEY_ID = "Test Crypto Key ID";
	public static final String TEST_CRYPTO_KEY_TYPE = "MockCryptoKeyType";
	public static final CryptoKeyUsage TEST_CRYPTO_KEY_USAGE = CryptoKeyUsage.ENCRYPTION;
	public static final CryptoKey TEST_BASE_64_CRYPTO_KEY = new CryptoKey();
	public static final String TEST_BASE_64_CRYPTO_KEY_ID = "Test Base 64 Crypto Key ID";
	public static final CryptoKey TEST_IDENTITY_CRYPTO_KEY = new CryptoKey();
	public static final String TEST_IDENTITY_CRYPTO_KEY_ID = "Test Identity Crypto Key ID";
	public static final String TEST_SOURCE_CLEAR_TEXT = "MockSourceValue";
	public static final String TEST_FINAL_CIPHERTEXT = "TEST CIPHERTEXT";
	public static final String TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME = "data";

	static {
		TEST_BASE_64_CRYPTO_KEY.setId(TEST_BASE_64_CRYPTO_KEY_ID);
		TEST_BASE_64_CRYPTO_KEY.setType(NonProdCryptoKeyTypes.BASE_64.getName());
		TEST_BASE_64_CRYPTO_KEY.setUsage(TEST_CRYPTO_KEY_USAGE);
		TEST_BASE_64_CRYPTO_KEY.setConfiguration(
			Map.of(PBKDF2EncryptionService.PASS_PHRASE, "Test Base 64 Key Material")
		);

		TEST_IDENTITY_CRYPTO_KEY.setId(TEST_IDENTITY_CRYPTO_KEY_ID);
		TEST_IDENTITY_CRYPTO_KEY.setType(NonProdCryptoKeyTypes.IDENTITY.getName());
		TEST_IDENTITY_CRYPTO_KEY.setUsage(TEST_CRYPTO_KEY_USAGE);
	}

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
