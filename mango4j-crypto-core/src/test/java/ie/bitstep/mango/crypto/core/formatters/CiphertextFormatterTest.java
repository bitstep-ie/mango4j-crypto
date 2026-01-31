package ie.bitstep.mango.crypto.core.formatters;

import com.fasterxml.jackson.databind.ObjectMapper;
import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.exceptions.CiphertextFormatterException;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CiphertextFormatterTest {

	private static final String TEST_CIPHERTEXT = "{\"cryptoKeyId\":\"" + TestData.TEST_CRYPTO_KEY_ID + "\",\"data\":{\"data\":\"" + TestData.TEST_SOURCE_CLEAR_TEXT + "\"}}";

	@Mock
	private CryptoKeyProvider cryptoKeyProvider;

	@Mock
	private ObjectMapperFactory objectMapperFactory;

	@InjectMocks
	private CiphertextFormatter ciphertextFormatter;

	private CryptoKey testCryptoKey;

	@BeforeEach
	void setup() {
		testCryptoKey = TestData.testCryptoKey();
		when(objectMapperFactory.objectMapper()).thenReturn(new ObjectMapper());
	}

	@Test
	void parse() {
		given(cryptoKeyProvider.getById(TestData.TEST_CRYPTO_KEY_ID)).willReturn(testCryptoKey);

		CiphertextContainer ciphertextContainer = ciphertextFormatter.parse(TEST_CIPHERTEXT);

		assertThat(ciphertextContainer.getCryptoKey()).isEqualTo(testCryptoKey);
		assertThat(ciphertextContainer.getData()).containsEntry(TestData.TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME, TestData.TEST_SOURCE_CLEAR_TEXT);
	}

	@Test
	void parseJsonProcessingException() {
		assertThatThrownBy(() -> ciphertextFormatter.parse("Badly formatted data"))
				.isInstanceOf(CiphertextFormatterException.class)
				.hasMessage("An error occurred trying to parse the String into a CiphertextContainer");
	}

	@Test
	void format() {
		CiphertextContainer testCipherTextContainer = new CiphertextContainer(testCryptoKey, Map.of(TestData.TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME, TestData.TEST_SOURCE_CLEAR_TEXT));

		assertThat(ciphertextFormatter.format(testCipherTextContainer)).isEqualTo(TEST_CIPHERTEXT);
	}

	@Test
	void formatJsonProcessingException() {
		RuntimeException cause = new RuntimeException("Test message");
		testCryptoKey = new CryptoKey() {
			@Override
			public String getId() {
				throw cause;
			}
		};
		CiphertextContainer testCipherTextContainer = new CiphertextContainer(testCryptoKey, Map.of(TestData.TEST_CIPHERTEXT_CONTAINER_DATA_ATTRIBUTE_NAME, TEST_CIPHERTEXT));

		assertThatThrownBy(() -> ciphertextFormatter.format(testCipherTextContainer))
				.isInstanceOf(CiphertextFormatterException.class)
				.hasMessage("An error occurred trying to format the CiphertextContainer into a String:java.lang.RuntimeException");
	}
}