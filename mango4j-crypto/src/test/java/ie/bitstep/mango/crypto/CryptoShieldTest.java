package ie.bitstep.mango.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import ie.bitstep.mango.crypto.core.exceptions.ActiveEncryptionKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.CiphertextFormatterException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.TransientCryptoException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.exceptions.DeserializationException;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.HighlyConfidentialObject;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntityWithNoEncryptFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntityWithNoEncryptionKeyIdAnnotation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithBothEncryptHmacAndCascadeEncryptFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithCollectionCascadeEncryptFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.NothingAnnotatedEntity;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies.MockHmacStrategyImpl;
import ie.bitstep.mango.reflection.utils.ReflectionUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static ie.bitstep.mango.crypto.testdata.TestData.PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CIPHERTEXT_CONTAINER;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_2;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ETHNICITY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ETHNICITY_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_FAVOURITE_COLOR;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_HIGHLY_CONFIDENTIAL_OBJECT;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_MOCK_ENCRYPTED_DATA;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_MOCK_SOURCE_CIPHERTEXT;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USERNAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USER_NAME_FIELD_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class CryptoShieldTest {

	public static final int TEST_POOL_SIZE = 10;
	@Mock
	private ObjectMapper mockedObjectMapper;

	@Mock
	private ObjectMapperFactory mockObjectMapperFactory;

	@Mock
	private ObjectNode mockObjectNode;

	@Mock
	private CiphertextFormatter mockCiphertextFormatter;

	@Mock
	private EncryptionService mockEncryptionService;

	@Mock
	private EncryptionServiceDelegate mockEncryptionServiceDelegate;

	@Mock
	private EncryptionServiceDelegate mockEncryptionServiceDelegate2;

	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	@Mock
	private RetryConfiguration mockRetryConfiguration;

	@Mock
	ScheduledExecutorService mockScheduledExecutorService;

	@Captor
	private ArgumentCaptor<ObjectNode> objectNodeArgumentCaptor;

	@Captor
	private ArgumentCaptor<Collection<HmacHolder>> hmacHolderArgumentCaptor;

	private ObjectNode objectNode;
	private TestMockHmacEntity testEntity;
	private CryptoShield cryptoShield;

	@BeforeEach
	void setup() {
		objectNode = new ObjectMapper().createObjectNode();
		MockHmacStrategyImpl.entityPassedToHmac = null;
		MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor = null;
		MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor = null;

		testEntity = new TestMockHmacEntity();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setHighlyConfidentialObject(TEST_HIGHLY_CONFIDENTIAL_OBJECT);

		given(mockEncryptionServiceDelegate.supportedCryptoKeyType()).willReturn(TEST_CRYPTO_KEY.getType());
	}

	@SuppressWarnings("unchecked")
	@Test
	void constructor() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockRetryConfiguration.poolSize()).willReturn(TEST_POOL_SIZE);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory,
				mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), mockRetryConfiguration);

		assertThat(cryptoShield).isNotNull();

		assertThat(getField(cryptoShield, "objectMapper")).isEqualTo(mockedObjectMapper);
		assertThat(getField(cryptoShield, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		CiphertextFormatter ciphertextFormatter = (CiphertextFormatter) getField(cryptoShield, "ciphertextFormatter");
		assertThat(getField(ciphertextFormatter, "objectMapperFactory")).isEqualTo(mockObjectMapperFactory);
		assertThat(getField(ciphertextFormatter, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		EncryptionService encryptionService = (EncryptionService) getField(cryptoShield, "encryptionService");
		assertThat((Map<String, EncryptionServiceDelegate>) getField(encryptionService, "encryptionServiceDelegates")).containsValue(mockEncryptionServiceDelegate);
		assertThat((CiphertextFormatter) getField(encryptionService, "ciphertextFormatter")).isEqualTo(ciphertextFormatter);
		assertThat((ObjectMapperFactory) getField(encryptionService, "objectMapperFactory")).isEqualTo(mockObjectMapperFactory);
		assertThat(getField(cryptoShield, "retryConfiguration")).isEqualTo(mockRetryConfiguration);
		assertThat(getField(cryptoShield, "annotatedEntityManager")).isInstanceOf(AnnotatedEntityManager.class);
	}

	@Test
	void constructorNullObjectMapper() {
		given(mockRetryConfiguration.poolSize()).willReturn(TEST_POOL_SIZE);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), null,
				mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), mockRetryConfiguration);

		assertThat(cryptoShield).isNotNull();

		assertThat(getField(cryptoShield, "objectMapper")).isInstanceOf(ObjectMapper.class);
		assertThat(getField(cryptoShield, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		CiphertextFormatter ciphertextFormatter = (CiphertextFormatter) getField(cryptoShield, "ciphertextFormatter");
		assertThat(getField(ciphertextFormatter, "objectMapperFactory")).isInstanceOf(ConfigurableObjectMapperFactory.class);
		assertThat(getField(ciphertextFormatter, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		EncryptionService encryptionService = (EncryptionService) getField(cryptoShield, "encryptionService");
		assertThat((Map<String, EncryptionServiceDelegate>) getField(encryptionService, "encryptionServiceDelegates")).containsValue(mockEncryptionServiceDelegate);
		assertThat((CiphertextFormatter) getField(encryptionService, "ciphertextFormatter")).isEqualTo(ciphertextFormatter);
		assertThat((ObjectMapperFactory) getField(encryptionService, "objectMapperFactory")).isInstanceOf(ConfigurableObjectMapperFactory.class);
		assertThat(getField(cryptoShield, "retryConfiguration")).isEqualTo(mockRetryConfiguration);
		assertThat(getField(cryptoShield, "annotatedEntityManager")).isInstanceOf(AnnotatedEntityManager.class);
	}

	@Test
	void encryptWithObject() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
	}

	@Test
	void encryptCollectionSuccess() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(List.of(testEntity));

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
	}

	@Test
	void encryptArraySuccess() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(new TestMockHmacEntity[]{testEntity});

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
	}

	@Test
	void encryptArrayPrimitiveException() {
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		assertThatThrownBy(() -> cryptoShield.encrypt(new int[]{}))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("encrypt() method doesn't support arrays of primitive types (int)");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	private void overrideDirectlyInstantiatedFieldsWithMocks() {
		overrideFieldWithMock(cryptoShield, "ciphertextFormatter", mockCiphertextFormatter);
		overrideFieldWithMock(cryptoShield, "encryptionService", mockEncryptionService);
	}

	private void overrideFieldWithMock(CryptoShield cryptoShield, String fieldName, Object mock) {
		try {
			ReflectionUtils.forceSetField(cryptoShield, fieldName, mock);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	void encryptNullEntity() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		cryptoShield.encrypt(null);

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	@Test
	void encryptNullSourceFieldValue() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);

		testEntity = new TestMockHmacEntity();
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);


		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);

		then(mockedObjectMapper).shouldHaveNoMoreInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	@Test
	void encryptNullConvertedValue() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(null);
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME)).isNull();
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
	}

	@Test
	void encryptNullJsonNodeConvertedValue() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(NullNode.getInstance());
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME)).isNull();
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
	}

	@Test
	void encryptNullMissingNodeConvertedValue() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(MissingNode.getInstance());
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME)).isNull();
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
	}

	@Test
	void encryptWithNoEncryptionKeyIdAnnotation() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		TestMockHmacEntityWithNoEncryptionKeyIdAnnotation entity = new TestMockHmacEntityWithNoEncryptionKeyIdAnnotation();
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);
		entity.setEthnicity(TEST_ETHNICITY);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntityWithNoEncryptionKeyIdAnnotation.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(entity);

		assertThat(entity.getEncryptionKeyId()).isNull();
		assertThat(entity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(entity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntityWithNoEncryptionKeyIdAnnotation.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
	}

	@Test
	void encryptNonTransientCiphertextFormatFailure() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willThrow(new CiphertextFormatterException("Issue with json"));

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		NonTransientCryptoException exception = assertThrows(NonTransientCryptoException.class, () ->
				cryptoShield.encrypt(testEntity)
		);
		assertThat(exception).isInstanceOf(CiphertextFormatterException.class);
		assertThat(exception.getMessage()).isEqualTo("Issue with json");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
	}

	@Test
	void encryptGeneralException() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willThrow(new RuntimeException("Test exception"));

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("An error occurred trying to create the ciphertext:class java.lang.RuntimeException");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
	}

	@Test
	void encryptFieldGetFailure() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		RuntimeException cause = new RuntimeException("Test Exception Message");
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willThrow(cause);


		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		NonTransientCryptoException exception = assertThrows(NonTransientCryptoException.class, () ->
				cryptoShield.encrypt(testEntity)
		);
		assertThat(exception).isInstanceOf(NonTransientCryptoException.class);
		assertThat(exception.getMessage()).isEqualTo("A RuntimeException error occurred trying to get the value of field: pan on type: TestMockHmacEntity");
	}

	@Test
	void encryptWithRetrySuccessOnFirstAttempt() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode())
				.willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofMillis(200), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);

		then(mockedObjectMapper).should(times(1)).createObjectNode();
	}

	@Test
	void encryptWithRetrySuccessOnLastAttempt() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		TransientCryptoException transientCryptoException = new TransientCryptoException("Test Transient Exception", new RuntimeException());
		given(mockedObjectMapper.createObjectNode())
				.willThrow(transientCryptoException, transientCryptoException)
				.willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofMillis(200), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.encrypt(testEntity);

		assertThat(testEntity.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);

		then(mockedObjectMapper).should(times(3)).createObjectNode();
	}

	@Test
	void encryptWithRetryAllRetriesFailAllRetriesFail() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		TransientCryptoException transientCryptoException = new TransientCryptoException("Test Transient Exception", new RuntimeException());
		given(mockedObjectMapper.createObjectNode())
				.willThrow(transientCryptoException);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofMillis(200), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isEqualTo(transientCryptoException)
				.hasMessage("Test Transient Exception");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);

		then(mockedObjectMapper).should(times(3)).createObjectNode();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void encryptWithRetryInterruptedExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		given(mockedFuture.get()).willThrow(new InterruptedException());
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Thread was interrupted during retry backoff sleep");
		assertThat(Thread.currentThread().isInterrupted()).isTrue();

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);

		then(mockedObjectMapper).should(times(0)).createObjectNode();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void encryptWithRetryExecutionExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		Exception cause = new RuntimeException("Test Runtime Exception");
		ExecutionException executionException = new ExecutionException("Test General Execution Exception", cause);
		given(mockedFuture.get()).willThrow(executionException);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasCause(cause)
				.hasMessage("An error occurred during retry attempt");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);

		then(mockedObjectMapper).should(times(0)).createObjectNode();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void encryptWithRetryNonTransientCryptoExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		Exception cause = new NonTransientCryptoException("Test Non Transient Crypto Exception");
		ExecutionException executionException = new ExecutionException("Test General Execution Exception", cause);
		given(mockedFuture.get()).willThrow(executionException);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isEqualTo(cause);

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);

		then(mockedObjectMapper).should(times(0)).createObjectNode();
	}

	@Test
	void getHmacStrategy() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		assertThat(cryptoShield.getHmacStrategy(testEntity).orElseThrow()).isInstanceOf(MockHmacStrategyImpl.class);
	}

	@Test
	void encryptNoCurrentEncryptionKey() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(null);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		assertThatThrownBy(() -> cryptoShield.encrypt(testEntity))
				.isInstanceOf(ActiveEncryptionKeyNotFoundException.class)
				.hasMessage("No active encryption key was found");

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);


		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	@Test
	void encryptNoCurrentEncryptionKeyButRekeyCryptoShieldDelegate() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		CryptoShieldDelegate mockCryptoShieldDelegate = Mockito.mock(CryptoShieldDelegate.class);
		given(mockCryptoShieldDelegate.getCurrentEncryptionKey()).willReturn(null);
		given(mockCryptoShieldDelegate.getHmacStrategy(testEntity)).willReturn(Optional.of(new MockHmacStrategyImpl(null, null)));

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		assertThatNoException().isThrownBy(() -> cryptoShield.encrypt(testEntity, mockCryptoShieldDelegate));

		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	@Test
	void encryptNoEncryptFields() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntityWithNoEncryptFields.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);

		TestMockHmacEntityWithNoEncryptFields entity = new TestMockHmacEntityWithNoEncryptFields();
		cryptoShield.encrypt(entity);

		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(entity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntityWithNoEncryptFields.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
	}

	@Test
	void encryptNoAnnotations() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(NothingAnnotatedEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);

		NothingAnnotatedEntity entity = new NothingAnnotatedEntity();
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);
		entity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		cryptoShield.encrypt(entity);

		assertThat(entity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isNull();
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isNull();

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();

	}

	@Test
	void encryptAndSerialize() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		TestMockHmacEntity result = cryptoShield.encryptAndSerialize(testEntity, e -> {
			e.setPan(null);
			e.setUserName(null);
			e.setEthnicity(null);
			e.setHighlyConfidentialObject(null);
			return e;
		});

		assertThat(result.getPan()).isEqualTo(TEST_PAN);
		assertThat(result.getUserName()).isEqualTo(TEST_USERNAME);
		assertThat(result.getEthnicity()).isEqualTo(TEST_ETHNICITY);

		assertThat(result.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(result.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
	}

	@Test
	void encryptAndSerializeExceptionGettingSourceFieldValues() throws NoSuchFieldException, IllegalAccessException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		AnnotatedEntityManager aem = (AnnotatedEntityManager) cryptoShield.getClass().getDeclaredField("annotatedEntityManager").get(cryptoShield);
		aem.getAllConfidentialFields(TestMockHmacEntity.class).forEach(field -> field.setAccessible(false));
		overrideDirectlyInstantiatedFieldsWithMocks();
		assertThatThrownBy(() -> cryptoShield.encryptAndSerialize(testEntity, e -> {
			e.setPan(null);
			e.setUserName(null);
			e.setEthnicity(null);
			e.setHighlyConfidentialObject(null);
			return e;
		}))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("A IllegalAccessException error occurred trying to get the value of field: pan on type: TestMockHmacEntity");

		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
	}

	@Test
	void encryptAndSerializeExceptionResettingSourceFieldValues() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.createObjectNode()).willReturn(objectNode);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		assertThatThrownBy(() -> cryptoShield.encryptAndSerialize(testEntity, e -> {
			e.setPan(null);
			e.setUserName(null);
			e.setEthnicity(null);
			e.setHighlyConfidentialObject(null);
			return null;
		}))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("The supplied serialization function returned a null entity, so cannot reset source fields");

		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isEqualTo(testEntity);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getValue().get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getValue().get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
	}

	@Test
	void decryptSuccess() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);
		TextNode panNode = new TextNode(TEST_PAN);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willReturn(panNode);
		given(mockedObjectMapper.treeToValue(panNode, String.class)).willReturn(TEST_PAN);
		TextNode userNameNode = new TextNode(TEST_USERNAME);
		given(mockObjectNode.get(TEST_USER_NAME_FIELD_NAME)).willReturn(userNameNode);
		given(mockedObjectMapper.treeToValue(userNameNode, String.class)).willReturn(TEST_USERNAME);
		TextNode ethnicityNode = new TextNode(TEST_ETHNICITY);
		given(mockObjectNode.get(TEST_ETHNICITY_FIELD_NAME)).willReturn(ethnicityNode);
		given(mockedObjectMapper.treeToValue(ethnicityNode, String.class)).willReturn(TEST_ETHNICITY);

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockObjectNode.get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.treeToValue(highlyConfidentialObjectNode, HighlyConfidentialObject.class)).willReturn(TEST_HIGHLY_CONFIDENTIAL_OBJECT);


		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();
		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setEthnicity(null);
		testEntity.setHighlyConfidentialObject(null);
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield.decrypt(List.of(testEntity));

		assertThat(testEntity.getPan()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserName()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getHighlyConfidentialObject()).isEqualTo(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
	}

	@Test
	void decryptNullEntity() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setEthnicity(null);

		cryptoShield.decrypt(null);

		assertThat(testEntity.getEncryptionKeyId()).isNull();
		assertThat(testEntity.getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.entityPassedToHmac).isNull();
		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
	}

	@Test
	void decryptNullFieldSuccess() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(objectNode);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();
		testEntity.setPan(null);
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);
		cryptoShield.decrypt(testEntity);

		assertThat(testEntity.getPan()).isNull();
	}

	@Test
	void decryptNoExistingEncryptedData() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		TestMockHmacEntity entity = new TestMockHmacEntity();
		cryptoShield.decrypt(entity);

		assertThat(entity.getPan()).isNull();
	}

	@Test
	void decryptNoEncryptedFields() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntityWithNoEncryptFields.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		TestMockHmacEntityWithNoEncryptFields entity = new TestMockHmacEntityWithNoEncryptFields();

		cryptoShield.decrypt(entity);

		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
		then(mockedObjectMapper).shouldHaveNoInteractions();
	}

	@Test
	@Disabled("Revisit if we want to restrict to certain field types")
	void decryptExceptionWrongValueType() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(new ObjectNode(JsonNodeFactory.instance).put("pan", 234234234L));

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isInstanceOf(DeserializationException.class)
				.hasMessage("Field 'pan' is of type 'NUMBER'. Only String fields are currently supported");
	}

	@Test
	void decryptJsonNodeException() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willThrow(new RuntimeException());
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);

		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class),
				mockObjectMapperFactory,
				mockCryptoKeyProvider,
				List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("An error occurred trying to decrypt the ciphertext:class java.lang.RuntimeException");
	}

	@Test
	void decryptWithRetrySuccessOnLastAttempt() throws JsonProcessingException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		TransientCryptoException transientCryptoException = new TransientCryptoException("Test Transient Exception", new RuntimeException());
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA))
				.willThrow(transientCryptoException, transientCryptoException)
				.willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);
		TextNode panNode = new TextNode(TEST_PAN);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willReturn(panNode);
		given(mockedObjectMapper.treeToValue(panNode, String.class)).willReturn(TEST_PAN);
		TextNode userNameNode = new TextNode(TEST_USERNAME);
		given(mockObjectNode.get(TEST_USER_NAME_FIELD_NAME)).willReturn(userNameNode);
		given(mockedObjectMapper.treeToValue(userNameNode, String.class)).willReturn(TEST_USERNAME);
		TextNode ethnicityNode = new TextNode(TEST_ETHNICITY);
		given(mockObjectNode.get(TEST_ETHNICITY_FIELD_NAME)).willReturn(ethnicityNode);
		given(mockedObjectMapper.treeToValue(ethnicityNode, String.class)).willReturn(TEST_ETHNICITY);

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockObjectNode.get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.treeToValue(highlyConfidentialObjectNode, HighlyConfidentialObject.class)).willReturn(TEST_HIGHLY_CONFIDENTIAL_OBJECT);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofMillis(200), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();

		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setEthnicity(null);
		testEntity.setHighlyConfidentialObject(null);
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield.decrypt(testEntity);

		assertThat(testEntity.getPan()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserName()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getHighlyConfidentialObject()).isEqualTo(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	@Test
	void decryptWithRetryAllRetriesFailWithTransientException() throws ExecutionException, InterruptedException {
		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);

		TransientCryptoException cause = new TransientCryptoException("Test Transient Exception", new RuntimeException());
		ExecutionException executionException = new ExecutionException("Test General Execution Exception", cause);
		given(mockedFuture.get()).willThrow(executionException);

		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(200L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(600L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofMillis(200), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isEqualTo(cause);

		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockObjectMapperFactory).should().objectMapper();
		then(mockObjectMapperFactory).shouldHaveNoMoreInteractions();
		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void decryptWithRetryInterruptedExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		given(mockedFuture.get()).willThrow(new InterruptedException());
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Thread was interrupted during retry backoff sleep");
		assertThat(Thread.currentThread().isInterrupted()).isTrue();

		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockObjectMapperFactory).should().objectMapper();
		then(mockObjectMapperFactory).shouldHaveNoMoreInteractions();
		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void decryptWithRetryExecutionExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		Exception cause = new RuntimeException("Test Runtime Exception");
		ExecutionException executionException = new ExecutionException("Test General Execution Exception", cause);
		given(mockedFuture.get()).willThrow(executionException);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);


		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("An error occurred during retry attempt");

		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockObjectMapperFactory).should().objectMapper();
		then(mockObjectMapperFactory).shouldHaveNoMoreInteractions();
		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
	}

	@SuppressWarnings({"unchecked", "rawtypes"})
	@Test
	void decryptWithRetryNonTransientCryptoExceptionDuringFirstAttempt() throws InterruptedException, ExecutionException {
		ScheduledFuture mockedFuture = mock(ScheduledFuture.class);
		given(mockScheduledExecutorService.schedule(any(Runnable.class), eq(0L), eq(TimeUnit.MILLISECONDS)))
				.willReturn(mockedFuture);
		Exception cause = new NonTransientCryptoException("Test Non Transient Crypto Exception");
		ExecutionException executionException = new ExecutionException("Test General Execution Exception", cause);
		given(mockedFuture.get()).willThrow(executionException);

		RetryConfiguration retryConfiguration = new RetryConfiguration(TEST_POOL_SIZE, 3, Duration.ofSeconds(2), 2);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), retryConfiguration);
		overrideDirectlyInstantiatedFieldsWithMocks();
		overrideFieldWithMock(cryptoShield, "scheduler", mockScheduledExecutorService);

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Test Non Transient Crypto Exception");

		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockObjectMapperFactory).should().objectMapper();
		then(mockObjectMapperFactory).shouldHaveNoMoreInteractions();
		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
	}

	@Test
	void getCryptoKeyProvider() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);

		assertThat(cryptoShield.getCryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
	}

	@Test
	void generateHmacs() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionServiceDelegate2.supportedCryptoKeyType()).willReturn(TEST_CRYPTO_KEY_2.getType());
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY, TEST_CRYPTO_KEY_2));
		cryptoShield = new CryptoShield(List.of(TestMockHmacEntity.class),
				mockObjectMapperFactory,
				mockCryptoKeyProvider,
				List.of(mockEncryptionServiceDelegate, mockEncryptionServiceDelegate2), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		Collection<HmacHolder> hmacHolders = cryptoShield.generateHmacs(TEST_PAN);
		assertThat(hmacHolders).hasSize(2)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY) && hmacHolder.getValue().equals(TEST_PAN))
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY_2) && hmacHolder.getValue().equals(TEST_PAN));
		then(mockEncryptionService).should().hmac(hmacHolderArgumentCaptor.capture());

		assertThat(hmacHolderArgumentCaptor.getValue()).hasSize(2)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY) && hmacHolder.getValue().equals(TEST_PAN))
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY_2) && hmacHolder.getValue().equals(TEST_PAN));
	}

	@Test
	void cascadeEncryptSuccess() throws JsonProcessingException {
		String cascadeTestEntity2PanValue = "cascadeTestEntity2Pan";
		String cascadeTestEntity2UserNameValue = "cascadeTestEntity2UserName";
		String cascadeTestEntity2EthnicityValue = "cascadeTestEntity2Ethnicity";
		String cascadeTestEntity2FavouriteColorValue = "cascadeTestEntity2FavouriteColor";
		String cascadeTestEntity2HighlyConfidentialObjectTestValue = "cascadeTestEntity2HighlyConfidentialObjectTestValue";
		HighlyConfidentialObject cascadeTestEntity2HighlyConfidentialObject = new HighlyConfidentialObject();
		cascadeTestEntity2HighlyConfidentialObject.setHighlyConfidentialField(cascadeTestEntity2HighlyConfidentialObjectTestValue);

		given(mockedObjectMapper.createObjectNode()).willAnswer(invocationOnMock -> new ObjectMapper().createObjectNode());
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2PanValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2PanValue));

		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2UserNameValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2UserNameValue));

		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2EthnicityValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2EthnicityValue));

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);

		ObjectNode cascadeTestEntity2HighlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(cascadeTestEntity2HighlyConfidentialObjectTestValue));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2HighlyConfidentialObject, JsonNode.class)).willReturn(cascadeTestEntity2HighlyConfidentialObjectNode);

		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class, TestMockHmacEntity.class),
				mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		TestEntityWithBothEncryptHmacAndCascadeEncryptFields testEntityWithBothEncryptHmacAndCascadeEncryptFields = new TestEntityWithBothEncryptHmacAndCascadeEncryptFields();
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setPan(TEST_PAN);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setUserName(TEST_USERNAME);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEthnicity(TEST_ETHNICITY);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setHighlyConfidentialObject(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity1(this.testEntity);

		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		cascadeTestEntity2.setPan(cascadeTestEntity2PanValue);
		cascadeTestEntity2.setUserName(cascadeTestEntity2UserNameValue);
		cascadeTestEntity2.setEthnicity(cascadeTestEntity2EthnicityValue);
		cascadeTestEntity2.setFavouriteColor(cascadeTestEntity2FavouriteColorValue);
		cascadeTestEntity2.setHighlyConfidentialObject(cascadeTestEntity2HighlyConfidentialObject);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity2(cascadeTestEntity2);

		TestMockHmacEntity nonCascadedTestEntity = new TestMockHmacEntity();
		nonCascadedTestEntity.setPan("nonCascadedTestEntityPan");
		nonCascadedTestEntity.setUserName("nonCascadedTestEntityUserName");
		nonCascadedTestEntity.setEthnicity("nonCascadedTestEntityEthnicity");
		nonCascadedTestEntity.setFavouriteColor("nonCascadedTestEntityFavouriteColor");
		HighlyConfidentialObject nonCascadedTestEntityHighlyConfidentialObject = new HighlyConfidentialObject();
		nonCascadedTestEntityHighlyConfidentialObject.setHighlyConfidentialField("nonCascadedTestEntityHighlyConfidentialObjectTestValue");
		nonCascadedTestEntity.setHighlyConfidentialObject(nonCascadedTestEntityHighlyConfidentialObject);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity3NotTraversed(nonCascadedTestEntity);

		cryptoShield.encrypt(testEntityWithBothEncryptHmacAndCascadeEncryptFields);

		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getTestMockHmacEntity1().getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getTestMockHmacEntity1().getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getTestMockHmacEntity3NotTraversed().getEncryptionKeyId()).isNull();
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getTestMockHmacEntity3NotTraversed().getEncryptedData()).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(2).get(PAN_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2PanValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(2).get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2UserNameValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(2).get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2EthnicityValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(2).get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(cascadeTestEntity2HighlyConfidentialObjectNode);
	}

	@Test
	void cascadeEncryptCollectionSuccess() throws JsonProcessingException {
		String cascadeTestEntity2PanValue = "cascadeTestEntity2Pan";
		String cascadeTestEntity2UserNameValue = "cascadeTestEntity2UserName";
		String cascadeTestEntity2EthnicityValue = "cascadeTestEntity2Ethnicity";
		String cascadeTestEntity2FavouriteColorValue = "cascadeTestEntity2FavouriteColor";
		String cascadeTestEntity2HighlyConfidentialObjectTestValue = "cascadeTestEntity2HighlyConfidentialObjectTestValue";
		HighlyConfidentialObject cascadeTestEntity2HighlyConfidentialObject = new HighlyConfidentialObject();
		cascadeTestEntity2HighlyConfidentialObject.setHighlyConfidentialField(cascadeTestEntity2HighlyConfidentialObjectTestValue);

		given(mockedObjectMapper.createObjectNode()).willAnswer(invocationOnMock -> new ObjectMapper().createObjectNode());
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2PanValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2PanValue));

		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2UserNameValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2UserNameValue));

		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2EthnicityValue, JsonNode.class)).willReturn(new TextNode(cascadeTestEntity2EthnicityValue));

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);

		ObjectNode cascadeTestEntity2HighlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(cascadeTestEntity2HighlyConfidentialObjectTestValue));
		given(mockedObjectMapper.convertValue(cascadeTestEntity2HighlyConfidentialObject, JsonNode.class)).willReturn(cascadeTestEntity2HighlyConfidentialObjectNode);

		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestEntityWithCollectionCascadeEncryptFields.class, TestMockHmacEntity.class),
				mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		cascadeTestEntity2.setPan(cascadeTestEntity2PanValue);
		cascadeTestEntity2.setUserName(cascadeTestEntity2UserNameValue);
		cascadeTestEntity2.setEthnicity(cascadeTestEntity2EthnicityValue);
		cascadeTestEntity2.setFavouriteColor(cascadeTestEntity2FavouriteColorValue);
		cascadeTestEntity2.setHighlyConfidentialObject(cascadeTestEntity2HighlyConfidentialObject);
		TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields = new TestEntityWithCollectionCascadeEncryptFields();
		testEntityWithCollectionCascadeEncryptFields.setTestMockHmacEntities(List.of(testEntity, cascadeTestEntity2));

		cryptoShield.encrypt(testEntityWithCollectionCascadeEncryptFields);

		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(1).getEncryptionKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(1).getEncryptedData()).isEqualTo(TEST_MOCK_ENCRYPTED_DATA);
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);

		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(PAN_FIELD_NAME).asText()).isEqualTo(TEST_PAN);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(TEST_USERNAME);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(TEST_ETHNICITY);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(0).get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(highlyConfidentialObjectNode);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(PAN_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2PanValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_USER_NAME_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2UserNameValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_ETHNICITY_FIELD_NAME).asText()).isEqualTo(cascadeTestEntity2EthnicityValue);
		assertThat(objectNodeArgumentCaptor.getAllValues().get(1).get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).isEqualTo(cascadeTestEntity2HighlyConfidentialObjectNode);
	}

	@Test
	void cascadeEncryptNullCollectionSuccess() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);

		cryptoShield = new CryptoShield(List.of(TestEntityWithCollectionCascadeEncryptFields.class, TestMockHmacEntity.class),
				mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields = new TestEntityWithCollectionCascadeEncryptFields();

		cryptoShield.encrypt(testEntityWithCollectionCascadeEncryptFields);

		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities()).isNull();
		assertThat(MockHmacStrategyImpl.annotatedEntityClassPassedToConstructor).isEqualTo(TestMockHmacEntity.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor).isInstanceOf(HmacStrategyHelper.class);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.cryptoKeyProvider()).isEqualTo(mockCryptoKeyProvider);
		assertThat(MockHmacStrategyImpl.hmacStrategyHelperPassedToConstructor.encryptionService()).isInstanceOf(EncryptionService.class);

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockEncryptionServiceDelegate2).shouldHaveNoInteractions();
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
	}

	@Test
	void cascadeEncryptExceptionGettingCascadedField() throws JsonProcessingException, NoSuchFieldException, IllegalAccessException {
		String cascadeTestEntity2PanValue = "cascadeTestEntity2Pan";
		String cascadeTestEntity2UserNameValue = "cascadeTestEntity2UserName";
		String cascadeTestEntity2EthnicityValue = "cascadeTestEntity2Ethnicity";
		String cascadeTestEntity2FavouriteColorValue = "cascadeTestEntity2FavouriteColor";
		String cascadeTestEntity2HighlyConfidentialObjectTestValue = "cascadeTestEntity2HighlyConfidentialObjectTestValue";
		HighlyConfidentialObject cascadeTestEntity2HighlyConfidentialObject = new HighlyConfidentialObject();
		cascadeTestEntity2HighlyConfidentialObject.setHighlyConfidentialField(cascadeTestEntity2HighlyConfidentialObjectTestValue);

		given(mockedObjectMapper.createObjectNode()).willAnswer(invocationOnMock -> new ObjectMapper().createObjectNode());
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockedObjectMapper.convertValue(TEST_PAN, JsonNode.class)).willReturn(new TextNode(TEST_PAN));
		given(mockedObjectMapper.convertValue(TEST_USERNAME, JsonNode.class)).willReturn(new TextNode(TEST_USERNAME));
		given(mockedObjectMapper.convertValue(TEST_ETHNICITY, JsonNode.class)).willReturn(new TextNode(TEST_ETHNICITY));
		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockedObjectMapper.convertValue(TEST_HIGHLY_CONFIDENTIAL_OBJECT, JsonNode.class)).willReturn(highlyConfidentialObjectNode);

		given(mockedObjectMapper.writeValueAsString(objectNodeArgumentCaptor.capture())).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockCryptoKeyProvider.getCurrentEncryptionKey()).willReturn(TEST_CRYPTO_KEY);
		given(mockEncryptionService.encrypt(TEST_CRYPTO_KEY, TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(TEST_CIPHERTEXT_CONTAINER);
		given(mockCiphertextFormatter.format(TEST_CIPHERTEXT_CONTAINER)).willReturn(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield = new CryptoShield(List.of(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class, TestMockHmacEntity.class),
				mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		TestEntityWithBothEncryptHmacAndCascadeEncryptFields testEntityWithBothEncryptHmacAndCascadeEncryptFields = new TestEntityWithBothEncryptHmacAndCascadeEncryptFields();
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setPan(TEST_PAN);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setUserName(TEST_USERNAME);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEthnicity(TEST_ETHNICITY);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setHighlyConfidentialObject(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity1(this.testEntity);

		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		cascadeTestEntity2.setPan(cascadeTestEntity2PanValue);
		cascadeTestEntity2.setUserName(cascadeTestEntity2UserNameValue);
		cascadeTestEntity2.setEthnicity(cascadeTestEntity2EthnicityValue);
		cascadeTestEntity2.setFavouriteColor(cascadeTestEntity2FavouriteColorValue);
		cascadeTestEntity2.setHighlyConfidentialObject(cascadeTestEntity2HighlyConfidentialObject);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity2(cascadeTestEntity2);

		TestMockHmacEntity nonCascadedTestEntity = new TestMockHmacEntity();
		nonCascadedTestEntity.setPan("nonCascadedTestEntityPan");
		nonCascadedTestEntity.setUserName("nonCascadedTestEntityUserName");
		nonCascadedTestEntity.setEthnicity("nonCascadedTestEntityEthnicity");
		nonCascadedTestEntity.setFavouriteColor("nonCascadedTestEntityFavouriteColor");
		HighlyConfidentialObject nonCascadedTestEntityHighlyConfidentialObject = new HighlyConfidentialObject();
		nonCascadedTestEntityHighlyConfidentialObject.setHighlyConfidentialField("nonCascadedTestEntityHighlyConfidentialObjectTestValue");
		nonCascadedTestEntity.setHighlyConfidentialObject(nonCascadedTestEntityHighlyConfidentialObject);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity3NotTraversed(nonCascadedTestEntity);

		AnnotatedEntityManager aem = (AnnotatedEntityManager) cryptoShield.getClass().getDeclaredField("annotatedEntityManager").get(cryptoShield);
		aem.getFieldsToCascadeEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class).forEach(field -> field.setAccessible(false));

		assertThatThrownBy(() -> cryptoShield.encrypt(testEntityWithBothEncryptHmacAndCascadeEncryptFields))
				.isInstanceOf(NonTransientCryptoException.class);
	}

	@Test
	void decryptCascadeSuccess() throws JsonProcessingException {
		String cascadeTestEntity2PanValue = "cascadeTestEntity2Pan";
		String cascadeTestEntity2UserNameValue = "cascadeTestEntity2UserName";
		String cascadeTestEntity2EthnicityValue = "cascadeTestEntity2Ethnicity";
		String cascadeTestEntity2SourceCipherTextData = "{\"" + PAN_FIELD_NAME + "\": \"" + cascadeTestEntity2PanValue + "\"}";
		String cascadeTestEntity2CipherText = String.format("{\"cryptoKeyId\" : \"%s\", \"ciphertext\":\"%s\"}", TEST_CRYPTO_KEY.getId(), cascadeTestEntity2SourceCipherTextData.replaceAll("\"", "\\\\\""));

		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockEncryptionService.decrypt(cascadeTestEntity2CipherText)).willReturn(cascadeTestEntity2SourceCipherTextData);

		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);
		ObjectNode cascadeTestEntity2SourceCipherTextDataObjectNode = new ObjectMapper().createObjectNode();
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_PAN_FIELD_NAME, new TextNode(cascadeTestEntity2PanValue));
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_USER_NAME_FIELD_NAME, new TextNode(cascadeTestEntity2UserNameValue));
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_ETHNICITY_FIELD_NAME, new TextNode(cascadeTestEntity2EthnicityValue));
		given(mockedObjectMapper.readTree(cascadeTestEntity2SourceCipherTextData)).willReturn(cascadeTestEntity2SourceCipherTextDataObjectNode);

		TextNode panNode = new TextNode(TEST_PAN);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willReturn(panNode);
		TextNode cascadeTestEntity2PanNode = new TextNode(cascadeTestEntity2PanValue);
		given(mockedObjectMapper.treeToValue(panNode, String.class)).willReturn(TEST_PAN);
		given(mockedObjectMapper.treeToValue(cascadeTestEntity2PanNode, String.class)).willReturn(cascadeTestEntity2PanValue);
		TextNode userNameNode = new TextNode(TEST_USERNAME);
		given(mockObjectNode.get(TEST_USER_NAME_FIELD_NAME)).willReturn(userNameNode);
		given(mockedObjectMapper.treeToValue(userNameNode, String.class)).willReturn(TEST_USERNAME);
		TextNode ethnicityNode = new TextNode(TEST_ETHNICITY);
		given(mockObjectNode.get(TEST_ETHNICITY_FIELD_NAME)).willReturn(ethnicityNode);
		given(mockedObjectMapper.treeToValue(ethnicityNode, String.class)).willReturn(TEST_ETHNICITY);

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockObjectNode.get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.treeToValue(highlyConfidentialObjectNode, HighlyConfidentialObject.class)).willReturn(TEST_HIGHLY_CONFIDENTIAL_OBJECT);

		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		cascadeTestEntity2.setEncryptedData(cascadeTestEntity2CipherText);
		TestEntityWithBothEncryptHmacAndCascadeEncryptFields testEntityWithBothEncryptHmacAndCascadeEncryptFields = new TestEntityWithBothEncryptHmacAndCascadeEncryptFields();
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity2(cascadeTestEntity2);

		cryptoShield = new CryptoShield(List.of(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class, TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setPan(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setUserName(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEthnicity(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setHighlyConfidentialObject(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);

		cryptoShield.decrypt(testEntityWithBothEncryptHmacAndCascadeEncryptFields);

		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getPan()).isEqualTo(TEST_PAN);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getUserName()).isEqualTo(TEST_USERNAME);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getHighlyConfidentialObject()).isEqualTo(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
		assertThat(testEntityWithBothEncryptHmacAndCascadeEncryptFields.getTestMockHmacEntity2().getPan()).isEqualTo(cascadeTestEntity2PanValue);
	}

	@Test
	void decryptCollectionCascadeSuccess() throws JsonProcessingException {
		String cascadeTestEntity2PanValue = "cascadeTestEntity2Pan";
		String cascadeTestEntity2UserNameValue = "cascadeTestEntity2UserName";
		String cascadeTestEntity2EthnicityValue = "cascadeTestEntity2Ethnicity";
		String cascadeTestEntity2SourceCipherTextData = "{\"" + PAN_FIELD_NAME + "\": \"" + cascadeTestEntity2PanValue + "\"}";
		String cascadeTestEntity2CipherText = String.format("{\"cryptoKeyId\" : \"%s\", \"ciphertext\":\"%s\"}", TEST_CRYPTO_KEY.getId(), cascadeTestEntity2SourceCipherTextData.replaceAll("\"", "\\\\\""));

		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockEncryptionService.decrypt(cascadeTestEntity2CipherText)).willReturn(cascadeTestEntity2SourceCipherTextData);

		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);
		ObjectNode cascadeTestEntity2SourceCipherTextDataObjectNode = new ObjectMapper().createObjectNode();
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_PAN_FIELD_NAME, new TextNode(cascadeTestEntity2PanValue));
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_USER_NAME_FIELD_NAME, new TextNode(cascadeTestEntity2UserNameValue));
		cascadeTestEntity2SourceCipherTextDataObjectNode.set(TEST_ETHNICITY_FIELD_NAME, new TextNode(cascadeTestEntity2EthnicityValue));
		given(mockedObjectMapper.readTree(cascadeTestEntity2SourceCipherTextData)).willReturn(cascadeTestEntity2SourceCipherTextDataObjectNode);

		TextNode panNode = new TextNode(TEST_PAN);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willReturn(panNode);
		TextNode cascadeTestEntity2PanNode = new TextNode(cascadeTestEntity2PanValue);
		given(mockedObjectMapper.treeToValue(panNode, String.class)).willReturn(TEST_PAN);
		given(mockedObjectMapper.treeToValue(cascadeTestEntity2PanNode, String.class)).willReturn(cascadeTestEntity2PanValue);
		TextNode userNameNode = new TextNode(TEST_USERNAME);
		given(mockObjectNode.get(TEST_USER_NAME_FIELD_NAME)).willReturn(userNameNode);
		given(mockedObjectMapper.treeToValue(userNameNode, String.class)).willReturn(TEST_USERNAME);
		TextNode ethnicityNode = new TextNode(TEST_ETHNICITY);
		given(mockObjectNode.get(TEST_ETHNICITY_FIELD_NAME)).willReturn(ethnicityNode);
		given(mockedObjectMapper.treeToValue(ethnicityNode, String.class)).willReturn(TEST_ETHNICITY);

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockObjectNode.get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.treeToValue(highlyConfidentialObjectNode, HighlyConfidentialObject.class)).willReturn(TEST_HIGHLY_CONFIDENTIAL_OBJECT);

		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setEthnicity(null);
		testEntity.setHighlyConfidentialObject(null);
		testEntity.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);
		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		cascadeTestEntity2.setEncryptedData(cascadeTestEntity2CipherText);
		TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields = new TestEntityWithCollectionCascadeEncryptFields();
		testEntityWithCollectionCascadeEncryptFields.setTestMockHmacEntities(List.of(testEntity, cascadeTestEntity2));

		cryptoShield = new CryptoShield(List.of(TestEntityWithCollectionCascadeEncryptFields.class, TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.decrypt(testEntityWithCollectionCascadeEncryptFields);

		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getPan()).isEqualTo(TEST_PAN);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getUserName()).isEqualTo(TEST_USERNAME);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(0).getHighlyConfidentialObject()).isEqualTo(TEST_HIGHLY_CONFIDENTIAL_OBJECT);
		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities().get(1).getPan()).isEqualTo(cascadeTestEntity2PanValue);
	}

	@Test
	void decryptNullCollectionCascadeSuccess() {
		TestEntityWithCollectionCascadeEncryptFields testEntityWithCollectionCascadeEncryptFields = new TestEntityWithCollectionCascadeEncryptFields();

		cryptoShield = new CryptoShield(List.of(TestEntityWithCollectionCascadeEncryptFields.class, TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();

		cryptoShield.decrypt(testEntityWithCollectionCascadeEncryptFields);

		assertThat(testEntityWithCollectionCascadeEncryptFields.getTestMockHmacEntities()).isNull();

		then(mockedObjectMapper).shouldHaveNoInteractions();
		then(mockObjectNode).shouldHaveNoInteractions();
		then(mockCiphertextFormatter).shouldHaveNoInteractions();
		then(mockEncryptionService).shouldHaveNoInteractions();
		then(mockEncryptionServiceDelegate2).shouldHaveNoInteractions();
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
	}

	@Test
	void decryptCascadeExceptionGettingCascadedField() throws JsonProcessingException, NoSuchFieldException, IllegalAccessException {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockEncryptionService.decrypt(TEST_MOCK_ENCRYPTED_DATA)).willReturn(TEST_MOCK_SOURCE_CIPHERTEXT);
		given(mockedObjectMapper.readTree(TEST_MOCK_SOURCE_CIPHERTEXT)).willReturn(mockObjectNode);
		TextNode panNode = new TextNode(TEST_PAN);
		given(mockObjectNode.get(TEST_PAN_FIELD_NAME)).willReturn(panNode);
		given(mockedObjectMapper.treeToValue(panNode, String.class)).willReturn(TEST_PAN);
		TextNode userNameNode = new TextNode(TEST_USERNAME);
		given(mockObjectNode.get(TEST_USER_NAME_FIELD_NAME)).willReturn(userNameNode);
		given(mockedObjectMapper.treeToValue(userNameNode, String.class)).willReturn(TEST_USERNAME);
		TextNode ethnicityNode = new TextNode(TEST_ETHNICITY);
		given(mockObjectNode.get(TEST_ETHNICITY_FIELD_NAME)).willReturn(ethnicityNode);
		given(mockedObjectMapper.treeToValue(ethnicityNode, String.class)).willReturn(TEST_ETHNICITY);

		ObjectNode highlyConfidentialObjectNode = new ObjectNode(JsonNodeFactory.instance);
		highlyConfidentialObjectNode.set(TEST_HIGHLY_CONFIDENTIAL_FIELD_NAME, new TextNode(SOME_HIGHLY_CONFIDENTIAL_OBJECT_TEST_VALUE));
		given(mockObjectNode.get(TEST_HIGHLY_CONFIDENTIAL_OBJECT_FIELD_NAME)).willReturn(highlyConfidentialObjectNode);
		given(mockedObjectMapper.treeToValue(highlyConfidentialObjectNode, HighlyConfidentialObject.class)).willReturn(TEST_HIGHLY_CONFIDENTIAL_OBJECT);

		TestEntityWithBothEncryptHmacAndCascadeEncryptFields testEntityWithBothEncryptHmacAndCascadeEncryptFields = new TestEntityWithBothEncryptHmacAndCascadeEncryptFields();
		TestMockHmacEntity cascadeTestEntity2 = new TestMockHmacEntity();
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setTestMockHmacEntity2(cascadeTestEntity2);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setPan(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setUserName(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEthnicity(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setHighlyConfidentialObject(null);
		testEntityWithBothEncryptHmacAndCascadeEncryptFields.setEncryptedData(TEST_MOCK_ENCRYPTED_DATA);
		cryptoShield = new CryptoShield(List.of(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class, TestMockHmacEntity.class), mockObjectMapperFactory, mockCryptoKeyProvider, List.of(mockEncryptionServiceDelegate), null);
		overrideDirectlyInstantiatedFieldsWithMocks();
		AnnotatedEntityManager aem = (AnnotatedEntityManager) cryptoShield.getClass().getDeclaredField("annotatedEntityManager").get(cryptoShield);
		aem.getFieldsToCascadeEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class).forEach(field -> field.setAccessible(false));

		assertThatThrownBy(() -> cryptoShield.decrypt(testEntityWithBothEncryptHmacAndCascadeEncryptFields))
				.isInstanceOf(NonTransientCryptoException.class);
	}

	@SuppressWarnings("unchecked")
	@Test
	void testBuilderBuildsCryptoShieldWithCorrectFieldsUsingReflection() {
		given(mockObjectMapperFactory.objectMapper()).willReturn(mockedObjectMapper);
		given(mockRetryConfiguration.poolSize()).willReturn(TEST_POOL_SIZE);

		CryptoShield shield = new CryptoShield.Builder()
				.withAnnotatedEntities(List.of(TestAnnotatedEntityForListHmacFieldStrategy.class))
				.withObjectMapperFactory(mockObjectMapperFactory)
				.withCryptoKeyProvider(mockCryptoKeyProvider)
				.withEncryptionServiceDelegates(List.of(mockEncryptionServiceDelegate))
				.withRetryConfiguration(mockRetryConfiguration)
				.build();

		assertThat(getField(shield, "objectMapper")).isEqualTo(mockedObjectMapper);
		assertThat(getField(shield, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		EncryptionService encryptionService = (EncryptionService) getField(shield, "encryptionService");
		assertThat((Map<String, EncryptionServiceDelegate>) getField(encryptionService, "encryptionServiceDelegates")).containsValue(mockEncryptionServiceDelegate);
		assertThat(getField(shield, "retryConfiguration")).isEqualTo(mockRetryConfiguration);
		CiphertextFormatter ciphertextFormatter = (CiphertextFormatter) getField(shield, "ciphertextFormatter");
		assertThat(getField(ciphertextFormatter, "objectMapperFactory")).isEqualTo(mockObjectMapperFactory);
		assertThat(getField(ciphertextFormatter, "cryptoKeyProvider")).isEqualTo(mockCryptoKeyProvider);
		assertThat(getField(shield, "annotatedEntityManager")).isInstanceOf(AnnotatedEntityManager.class);
	}

	// Helper method to access private fields via reflection
	private static Object getField(Object target, String fieldName) {
		try {
			Field field = target.getClass().getDeclaredField(fieldName);
			field.setAccessible(true);
			return field.get(target);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}