package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willDoNothing;

@ExtendWith(MockitoExtension.class)
class EncryptionServiceTest {

	private EncryptionService encryptionService;

	@Mock
	private EncryptionServiceDelegate mockEncryptionServiceDelegate;

	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	@Mock
	private ObjectMapperFactory mockObjectMapperFactory;

	@Mock
	private CiphertextFormatter mockCiphertextFormatter;

	@Captor
	private ArgumentCaptor<List<HmacHolder>> hmacHolderArgumentCapture;

	@Captor
	private ArgumentCaptor<EncryptionService> encryptionServiceArgumentCapture;

	@Captor
	private ArgumentCaptor<CiphertextContainer> ciphertextContainerArgumentCapture;

	private CryptoKey testMockCryptoKey;
	private CiphertextContainer testCiphertextContainer;
	private HmacHolder testMockHmacHolder;
	private List<HmacHolder> testMockHmacHolders;
	private CiphertextFormatter cipherTextFormatter;

	@BeforeEach
	void setup() {
		testMockCryptoKey = TestData.testCryptoKey();
		testCiphertextContainer = TestData.testCipherTextContainer();
		testMockHmacHolder = TestData.testHmacHolder();
		testMockHmacHolders = List.of(testMockHmacHolder);
		cipherTextFormatter = new CiphertextFormatter(mockCryptoKeyProvider, new ConfigurableObjectMapperFactory());
	}

	@Test
	void constructorWithObjectMapperFactory() throws NoSuchFieldException, IllegalAccessException {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);

		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider, mockObjectMapperFactory);

		Field objectMapperFactoryField = EncryptionService.class.getDeclaredField("objectMapperFactory");
		objectMapperFactoryField.setAccessible(true);
		assertThat(objectMapperFactoryField.get(encryptionService)).isEqualTo(mockObjectMapperFactory);
	}

	@Test
	void constructorWithCiphertextFormatterAndObjectMapperFactory() throws NoSuchFieldException, IllegalAccessException {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);

		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCiphertextFormatter, mockObjectMapperFactory);

		Field ciphertextFormatterField = EncryptionService.class.getDeclaredField("ciphertextFormatter");
		ciphertextFormatterField.setAccessible(true);
		assertThat(ciphertextFormatterField.get(encryptionService)).isEqualTo(mockCiphertextFormatter);

		Field objectMapperFactoryField = EncryptionService.class.getDeclaredField("objectMapperFactory");
		objectMapperFactoryField.setAccessible(true);
		assertThat(objectMapperFactoryField.get(encryptionService)).isEqualTo(mockObjectMapperFactory);
	}

	@Test
	void objectMapper() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);

		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		assertThat(encryptionService.getObjectMapperFactory()).isInstanceOf(ConfigurableObjectMapperFactory.class);
	}

	@Test
	void encrypt() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);
		given(mockEncryptionServiceDelegate.encrypt(testMockCryptoKey, TestData.TEST_SOURCE_CLEAR_TEXT)).willReturn(testCiphertextContainer);
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		CiphertextContainer result = encryptionService.encrypt(testMockCryptoKey, TestData.TEST_SOURCE_CLEAR_TEXT);

		assertThat(result).isEqualTo(testCiphertextContainer);
	}

	@Test
	void encryptCryptoKeyTypeNotRegistered() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn("SomeOtherKeyType");
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		assertThatThrownBy(() -> encryptionService.encrypt(testMockCryptoKey, TestData.TEST_SOURCE_CLEAR_TEXT))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:Test Crypto Key ID, type:MockCryptoKeyType, usage:ENCRYPTION]");
	}

	@Test
	void encryptNullCryptoKeyType() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn("SomeOtherKeyType");
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);
		testMockCryptoKey.setType(null);

		assertThatThrownBy(() -> encryptionService.encrypt(testMockCryptoKey, TestData.TEST_SOURCE_CLEAR_TEXT))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:Test Crypto Key ID, type:null, usage:ENCRYPTION]");
	}

	@Test
	void encryptBatch() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);
		given(mockEncryptionServiceDelegate.encrypt(testMockCryptoKey, List.of(TestData.TEST_SOURCE_CLEAR_TEXT))).willReturn(List.of(testCiphertextContainer));
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		List<CiphertextContainer> result = encryptionService.encrypt(testMockCryptoKey, List.of(TestData.TEST_SOURCE_CLEAR_TEXT));

		assertThat(result).contains(testCiphertextContainer);
	}

	@Test
	void decryptString() {
		given(mockCryptoKeyProvider.getById(TestData.TEST_CRYPTO_KEY_ID)).willReturn(testMockCryptoKey);
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);
		given(mockEncryptionServiceDelegate.decrypt(ciphertextContainerArgumentCapture.capture())).willReturn(TestData.TEST_SOURCE_CLEAR_TEXT);
		given(mockCryptoKeyProvider.getById(TestData.TEST_CRYPTO_KEY_ID)).willReturn(TestData.testCryptoKey());
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		String result = encryptionService.decrypt(cipherTextFormatter.format(testCiphertextContainer));

		assertThat(result).isEqualTo(TestData.TEST_SOURCE_CLEAR_TEXT);
		assertThat(ciphertextContainerArgumentCapture.getValue().getCryptoKey()).isEqualTo(testMockCryptoKey);
		assertThat(ciphertextContainerArgumentCapture.getValue().getData()).isEqualTo(testCiphertextContainer.getData());
	}

	@Test
	void decryptStringCryptoKeyTypeNotRegistered() {
		testCiphertextContainer = TestData.testCipherTextContainer();
		given(mockCryptoKeyProvider.getById(TestData.TEST_CRYPTO_KEY_ID)).willReturn(TestData.testCryptoKey());
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn("SomeOtherKeyType");
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		String cipher = cipherTextFormatter.format(testCiphertextContainer);
		assertThatThrownBy(() -> encryptionService.decrypt(cipher))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:Test Crypto Key ID, type:MockCryptoKeyType, usage:ENCRYPTION]");
	}

	@Test
	void hmac() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TestData.TEST_CRYPTO_KEY_TYPE);
		willDoNothing().given(mockEncryptionServiceDelegate).hmac(hmacHolderArgumentCapture.capture());
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		encryptionService.hmac(testMockHmacHolders);

		assertThat(hmacHolderArgumentCapture.getValue()).hasSize(1);
		assertThat(hmacHolderArgumentCapture.getValue().get(0)).isEqualTo(testMockHmacHolder);
	}

	@Test
	void hmacCryptoKeyTypeNotRegistered() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn("SomeOtherKeyType");
		willDoNothing().given(mockEncryptionServiceDelegate).setEncryptionServiceReference(encryptionServiceArgumentCapture.capture());
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);

		assertThatThrownBy(() -> encryptionService.hmac(testMockHmacHolders))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:Test Crypto Key ID, type:MockCryptoKeyType, usage:ENCRYPTION]");
		assertThat(encryptionServiceArgumentCapture.getValue()).isEqualTo(encryptionService);
		then(mockEncryptionServiceDelegate).shouldHaveNoMoreInteractions();
	}

	@Test
	void hmacNullCryptoKeyType() {
		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn("SomeOtherKeyType");
		willDoNothing().given(mockEncryptionServiceDelegate).setEncryptionServiceReference(encryptionServiceArgumentCapture.capture());
		encryptionService = new EncryptionService(List.of(mockEncryptionServiceDelegate), mockCryptoKeyProvider);
		testMockHmacHolder.getCryptoKey().setType(null);

		assertThatThrownBy(() -> encryptionService.hmac(testMockHmacHolders))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:Test Crypto Key ID, type:null, usage:ENCRYPTION]");
		assertThat(encryptionServiceArgumentCapture.getValue()).isEqualTo(encryptionService);
		then(mockEncryptionServiceDelegate).shouldHaveNoMoreInteractions();
	}
}