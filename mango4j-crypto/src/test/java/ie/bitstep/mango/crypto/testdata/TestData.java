package ie.bitstep.mango.crypto.testdata;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.HighlyConfidentialObject;
import ie.bitstep.mango.crypto.enums.TestCryptoKeyTypes;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

public class TestData {

	public static final String TEST_NEW_CRYPTO_KEY_TYPE = "Test CryptoKeyType";
	public static final String TEST_IDENTITY_CRYPTO_KEY_ID = "Test Identity Crypto Key ID";
	public static final String MOCK_TEST_KEY_TYPE = "MockTestKey";
	public static final String TEST_CRYPTO_KEY_ID = "TestCryptoKeyId";

	public static final CryptoKey TEST_CRYPTO_KEY;
	public static final CryptoKey TEST_CRYPTO_KEY_2;

	static {
		TEST_CRYPTO_KEY = new CryptoKey();
		TEST_CRYPTO_KEY.setId(TEST_CRYPTO_KEY_ID);
		TEST_CRYPTO_KEY.setType(MOCK_TEST_KEY_TYPE);

		TEST_CRYPTO_KEY_2 = new CryptoKey();
		TEST_CRYPTO_KEY_2.setKeyStartTime(Instant.now());
		TEST_CRYPTO_KEY_2.setId(TEST_IDENTITY_CRYPTO_KEY_ID);
		TEST_CRYPTO_KEY_2.setType(TestCryptoKeyTypes.TEST.getName());
		TEST_CRYPTO_KEY_2.setUsage(CryptoKeyUsage.ENCRYPTION);
	}

	public static final String TEST_PAN = "5454545454545454";
	public static final String TEST_USERNAME = "username";
	public static final String TEST_FAVOURITE_COLOR = "green";
	public static final String TEST_ETHNICITY = "Vulcan";
	public static final String SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE = "someHighlyConfidentialObjectTestValue";
	public static final HighlyConfidentialObject TEST_HIGHLY_CONFIDENTIAL_OBJECT = new HighlyConfidentialObject();

	static {
		TEST_HIGHLY_CONFIDENTIAL_OBJECT.setHighlyConfidentialField(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE);
	}

	public static final String ENTITY_HMAC_FIELDS_FIELD_NAME = "entityHmacFields";
	public static final String ENTITY_HMAC_TOKENIZERS_FIELD_NAME = "entityHmacTokenizers";

	public static final String TEST_USER_NAME_FIELD_NAME = "userName";
	public static final String TEST_PAN_FIELD_NAME = "pan";
	public static final String TEST_ETHNICITY_FIELD_NAME = "ethnicity";
	public static final String TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME = "highlyConfidentialObject";
	public static final String TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME = "highlyConfidentialField";
	public static final String TEST_ENCRYPTED_DATA_FIELD_NAME = "encryptedData";
	public static final String PAN_FIELD_NAME = "pan";
	public static final String TEST_MOCK_SOURCE_CIPHERTEXT = "{\"" + PAN_FIELD_NAME + "\": \"" + TEST_PAN + "\"}";
	public static final String TEST_CRYPTO_KEY_DATA_ATTRIBUTE = "TEST_CIPHER_TEXT_ATTRIBUTE";
	public static final String TEST_MOCK_ENCRYPTED_DATA = String.format("{\"cryptoKeyId\" : \"%s\", \"ciphertext\":\"%s\"}", TEST_CRYPTO_KEY.getId(), TEST_MOCK_SOURCE_CIPHERTEXT.replaceAll("\"", "\\\\\""));
	public static final CiphertextContainer TEST_CIPHERTEXT_CONTAINER = new CiphertextContainer(TEST_CRYPTO_KEY, Map.of(TEST_CRYPTO_KEY_DATA_ATTRIBUTE, TEST_MOCK_SOURCE_CIPHERTEXT));

	public static CryptoKey testCryptoKey() {
		CryptoKey testCryptoKey = new CryptoKey();
		testCryptoKey.setId(TEST_CRYPTO_KEY_ID);
		testCryptoKey.setType(MOCK_TEST_KEY_TYPE);
		testCryptoKey.setKeyStartTime(Instant.now().minus(Duration.ofDays(1)));
		testCryptoKey.setCreatedDate(Instant.now());
		return testCryptoKey;
	}
}
