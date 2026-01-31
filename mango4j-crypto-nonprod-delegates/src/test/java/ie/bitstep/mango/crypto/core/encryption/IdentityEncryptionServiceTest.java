package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.core.encryption.IdentityEncryptionService.CIPHER_TEXT;
import static org.assertj.core.api.Assertions.assertThat;

class IdentityEncryptionServiceTest {

	private final IdentityEncryptionService identityEncryptionService = new IdentityEncryptionService();

	@Test
	void supportCryptoKeyType() {
		assertThat(identityEncryptionService.supportedCryptoKeyType()).isEqualTo(NonProdCryptoKeyTypes.IDENTITY.getName());
	}

	@Test
	void encrypt() {
		CiphertextContainer ciphertextContainer = identityEncryptionService.encrypt(TestData.TEST_IDENTITY_CRYPTO_KEY, TestData.TEST_SOURCE_CLEAR_TEXT);

		assertThat(ciphertextContainer.getCryptoKey()).isEqualTo(TestData.TEST_IDENTITY_CRYPTO_KEY);
		assertThat(ciphertextContainer.getData()).isEqualTo(Map.of(CIPHER_TEXT, TestData.TEST_SOURCE_CLEAR_TEXT));
	}

	@Test
	void decrypt() {
		CiphertextContainer ciphertextContainer = new CiphertextContainer(TestData.TEST_IDENTITY_CRYPTO_KEY, Map.of(CIPHER_TEXT, TestData.TEST_SOURCE_CLEAR_TEXT));

		assertThat(identityEncryptionService.decrypt(ciphertextContainer)).isEqualTo(TestData.TEST_SOURCE_CLEAR_TEXT);
	}

	@Test
	void hmac() {
		HmacHolder hmacHolder = new HmacHolder(TestData.TEST_IDENTITY_CRYPTO_KEY, TestData.TEST_SOURCE_CLEAR_TEXT);

		identityEncryptionService.hmac(List.of(hmacHolder));

		assertThat(hmacHolder.getCryptoKey()).isEqualTo(TestData.TEST_IDENTITY_CRYPTO_KEY);
		assertThat(hmacHolder.getValue()).isEqualTo(TestData.TEST_SOURCE_CLEAR_TEXT);
	}
}