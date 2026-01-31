package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class EncryptionServiceDelegateTest {

	public static final String CIPHER_TEXT_FIELD_NAME = "cipherText";
	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	private final EncryptionService encryptionService = new EncryptionService(List.of(), mockCryptoKeyProvider);
	private final CryptoKey testCryptoKey = TestData.testCryptoKey();

	static class ConfigPojo {
		public String algo;
	}

	@Test
	void setEncryptionServiceReference() {
		EncryptionServiceDelegate encryptionServiceDelegate = new TestEncryptionServiceDelegate();
		encryptionServiceDelegate.setEncryptionServiceReference(encryptionService);

		assertThat(encryptionServiceDelegate.encryptionService).isEqualTo(encryptionService);
	}

	@Test
	void encryptBatch() {
		EncryptionServiceDelegate encryptionServiceDelegate = new TestEncryptionServiceDelegate();
		encryptionServiceDelegate.setEncryptionServiceReference(encryptionService);

		List<CiphertextContainer> encryptedData = encryptionServiceDelegate.encrypt(testCryptoKey, List.of(TestData.TEST_SOURCE_CLEAR_TEXT));

		assertThat(encryptedData).hasSize(1);
		assertThat(encryptedData.get(0).getCryptoKey()).isEqualTo(testCryptoKey);
		assertThat(encryptedData.get(0).getData()).containsEntry(CIPHER_TEXT_FIELD_NAME, TestData.TEST_FINAL_CIPHERTEXT);
	}

	@Test
	void createConfigPojo() {
		EncryptionServiceDelegate encryptionServiceDelegate = new TestEncryptionServiceDelegate();
		encryptionServiceDelegate.setEncryptionServiceReference(encryptionService);

		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setConfiguration(
				Map.of("algo", "AES")
		);

		ConfigPojo configPojo = encryptionServiceDelegate.createConfigPojo(cryptoKey, ConfigPojo.class);

		assertThat(configPojo.algo).isEqualTo("AES");
	}

	private static class TestEncryptionServiceDelegate extends EncryptionServiceDelegate {
		@Override
		public String supportedCryptoKeyType() {
			return null;
		}

		@Override
		public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
			return new CiphertextContainer(encryptionKey, Map.of(CIPHER_TEXT_FIELD_NAME, TestData.TEST_FINAL_CIPHERTEXT));
		}

		@Override
		public String decrypt(CiphertextContainer ciphertextContainer) {
			return "";
		}

		@Override
		public void hmac(Collection<HmacHolder> hmacHolders) {
			throw new UnsupportedOperationException();
		}
	}
}
