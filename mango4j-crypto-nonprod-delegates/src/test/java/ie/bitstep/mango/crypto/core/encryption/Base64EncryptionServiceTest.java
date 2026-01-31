package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class Base64EncryptionServiceTest {

	private static final String CIPHER_TEXT = "cipherText";

	private final Base64EncryptionService base64EncryptionService = new Base64EncryptionService();

	@Test
	void supportCryptoKeyType() {
		assertThat(base64EncryptionService.supportedCryptoKeyType()).isEqualTo(NonProdCryptoKeyTypes.BASE_64.getName());
	}

	@Test
	void encrypt() {
		CiphertextContainer ciphertextContainer = base64EncryptionService.encrypt(TestData.TEST_BASE_64_CRYPTO_KEY, TestData.TEST_SOURCE_CLEAR_TEXT);

		Assertions.assertThat(ciphertextContainer.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		Assertions.assertThat(ciphertextContainer.getData()).containsEntry(CIPHER_TEXT, Base64.getEncoder().encodeToString(TestData.TEST_SOURCE_CLEAR_TEXT.getBytes()));
	}

	@Test
	void decrypt() {
		CiphertextContainer ciphertextContainer = new CiphertextContainer(
			TestData.TEST_BASE_64_CRYPTO_KEY,
			Map.of(CIPHER_TEXT, Base64.getEncoder().encodeToString(TestData.TEST_SOURCE_CLEAR_TEXT.getBytes()))
		);

		assertThat(base64EncryptionService.decrypt(ciphertextContainer)).isEqualTo(TestData.TEST_SOURCE_CLEAR_TEXT);
	}

	@Test
	void hmac() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_BASE_64_CRYPTO_KEY, TestData.TEST_SOURCE_CLEAR_TEXT);

		base64EncryptionService.hmac(List.of(hmacHolder));

		Assertions.assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		Assertions.assertThat(hmacHolder.getValue()).isEqualTo(Base64.getEncoder().encodeToString((TestData.TEST_BASE_64_CRYPTO_KEY.getId() + ":" + TestData.TEST_SOURCE_CLEAR_TEXT).getBytes()));
	}
}