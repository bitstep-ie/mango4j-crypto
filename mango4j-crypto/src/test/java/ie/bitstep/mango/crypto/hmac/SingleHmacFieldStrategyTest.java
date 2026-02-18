package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NoHmacKeysFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.exceptions.NoHmacFieldsFoundException;
import ie.bitstep.mango.crypto.testdata.TestData;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityForSingleHmacFieldStrategyHmacKeyIdMissing;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoTargetHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.TestAnnotatedEntityForSingleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.testdata.TestData.ENTITY_HMAC_KEY_ID_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.HMAC_KEY_ID_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ETHNICITY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_FAVOURITE_COLOR;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USERNAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USER_NAME_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.testCryptoKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class SingleHmacFieldStrategyTest {

	private static final String PAN_HMAC_FIELD_NAME = "panHmac";
	private static final String USER_NAME_HMAC_FIELD_NAME = "userNameHmac";
	private SingleHmacFieldStrategy singleHmacFieldStrategy;

	@Mock
	private HmacStrategyHelper mockHmacHelper;

	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	@Mock
	private EncryptionService mockEncryptionService;

	@Captor
	private ArgumentCaptor<List<HmacHolder>> hmacHolderArgumentCaptor;

	private TestAnnotatedEntityForSingleHmacFieldStrategy testEntity;
	private CryptoKey testCryptoKey;

	@BeforeEach
	void setup() {
		testCryptoKey = testCryptoKey();
		singleHmacFieldStrategy = new SingleHmacFieldStrategy(TestAnnotatedEntityForSingleHmacFieldStrategy.class, mockHmacHelper);

		testEntity = new TestAnnotatedEntityForSingleHmacFieldStrategy();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
	}

	@Test
	void registerSuccess() throws NoSuchFieldException, IllegalAccessException {
		singleHmacFieldStrategy = new SingleHmacFieldStrategy(TestAnnotatedEntityForSingleHmacFieldStrategy.class, mockHmacHelper);

		Map<Field, Field> entityHmacFields = getEntityHmacFieldsMap();
		Field expectedTargetPanHmacField = entityHmacFields.get(TestAnnotatedEntityForSingleHmacFieldStrategy.class.getDeclaredField(TEST_PAN_FIELD_NAME));
		expectedTargetPanHmacField.setAccessible(true);
		Field targetPanHmacField = TestAnnotatedEntityForSingleHmacFieldStrategy.class.getDeclaredField(PAN_HMAC_FIELD_NAME);
		targetPanHmacField.setAccessible(true);
		assertThat(expectedTargetPanHmacField).isEqualTo(targetPanHmacField);

		Field expectedTargetUserNameField = entityHmacFields.get(TestAnnotatedEntityForSingleHmacFieldStrategy.class.getDeclaredField(TEST_USER_NAME_FIELD_NAME));
		expectedTargetUserNameField.setAccessible(true);
		Field targetUserNameField = TestAnnotatedEntityForSingleHmacFieldStrategy.class.getDeclaredField(USER_NAME_HMAC_FIELD_NAME);
		targetUserNameField.setAccessible(true);

		assertThat(expectedTargetUserNameField).isEqualTo(targetUserNameField);
		assertThat(entityHmacFields).hasSize(2);

		Field registeredHmacKeyIdField = (Field) getHmacKeyIdField().get(singleHmacFieldStrategy);
		registeredHmacKeyIdField.setAccessible(true);
		Field actualHmacKeyIdField = TestAnnotatedEntityForSingleHmacFieldStrategy.class.getDeclaredField(HMAC_KEY_ID_FIELD_NAME);
		actualHmacKeyIdField.setAccessible(true);

		assertThat(registeredHmacKeyIdField).isEqualTo(actualHmacKeyIdField);
	}

	@Test
	void registerNonTransientHmacFields() {
		NonTransientCryptoException nonTransientCryptoException = assertThrows(NonTransientCryptoException.class, () -> new SingleHmacFieldStrategy(InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField.class, mockHmacHelper));

		assertThat(nonTransientCryptoException).hasMessage("InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField has a field named userName marked with @Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@Test
	void registerNoHmacFields() {
		assertThatThrownBy(() -> new SingleHmacFieldStrategy(TestAnnotatedEntityNoHmacFields.class, mockHmacHelper))
				.isInstanceOf(NoHmacFieldsFoundException.class)
				.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields' does not have any fields annotated with Hmac");
	}

	@Test
	void registerHmacSourceFieldsWithoutCorrespondingHmacTargetFields() {
		assertThatThrownBy(() -> new SingleHmacFieldStrategy(TestAnnotatedEntityNoTargetHmacFields.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'pan' does not have an associated field called 'panHmac'");
	}

	@Test
	void registerHmacKeyIdFieldMissing() {
		assertThatThrownBy(() -> new SingleHmacFieldStrategy(TestAnnotatedEntityForSingleHmacFieldStrategyHmacKeyIdMissing.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityForSingleHmacFieldStrategyHmacKeyIdMissing' uses the Single HMAC Strategy but does not have a field annotated with @HmacKeyId. It's mandatory to have a single String field annotated with @HmacKeyId when using the Single HMAC Strategy");
	}

	@SuppressWarnings("unchecked")
	private Map<Field, Field> getEntityHmacFieldsMap() throws NoSuchFieldException, IllegalAccessException {
		Field entityHmacFieldsField = SingleHmacFieldStrategy.class.getDeclaredField(TestData.ENTITY_HMAC_FIELDS_FIELD_NAME);
		entityHmacFieldsField.setAccessible(true);
		return (Map<Field, Field>) entityHmacFieldsField.get(singleHmacFieldStrategy);
	}

	private Field getHmacKeyIdField() throws NoSuchFieldException {
		Field entityHmacKeyIdField = SingleHmacFieldStrategy.class.getDeclaredField(ENTITY_HMAC_KEY_ID_FIELD_NAME);
		entityHmacKeyIdField.setAccessible(true);
		return entityHmacKeyIdField;
	}

	@Test
	void hmacSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getHmacKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}

	@Test
	void hmacNullValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TestData.TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		willDoNothing().given(mockEncryptionService).hmac(hmacHolderArgumentCaptor.capture());
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setPan(null);

		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isNull();
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		assertThat(hmacHolderArgumentCaptor.getValue()).hasSize(1);
		assertThat(hmacHolderArgumentCaptor.getValue().get(0).getCryptoKey()).isEqualTo(testCryptoKey);
		assertThat(hmacHolderArgumentCaptor.getValue().get(0).getValue()).isEqualTo(TEST_USERNAME);
		assertThat(hmacHolderArgumentCaptor.getValue().get(0).getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
	}

	@Test
	void hmacUnsupportedKeyTypeFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey));
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		willThrow(new UnsupportedKeyTypeException(testCryptoKey)).given(mockEncryptionService).hmac(hmacHolderArgumentCaptor.capture());

		assertThatThrownBy(() -> singleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(UnsupportedKeyTypeException.class)
				.hasMessage("No Encryption Service was registered for crypto key [id:TestCryptoKeyId, type:MockTestKey, usage:null]");
	}

	@Test
	void hmacHmacKeysListIsNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(null);

		assertThatThrownBy(() -> singleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NoHmacKeysFoundException.class)
				.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void hmacHmacKeysListIsEmpty() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());

		assertThatThrownBy(() -> singleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NoHmacKeysFoundException.class)
				.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	@DisplayName("When multiple HMAC keys exist, use the most recent one based on created date")
	void hmacHmacKeysListMultipleKeysWithCreatedDate() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		testCryptoKey.setCreatedDate(Instant.now().minus(Duration.ofDays(1)));
		CryptoKey secondHmacKey = testCryptoKey();
		secondHmacKey.setId("SecondHmacKeyId");
		secondHmacKey.setCreatedDate(Instant.now());

		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey, secondHmacKey));


		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		System.out.println(hmacHolderArgumentCaptor.getAllValues().get(0).get(0).getCryptoKey().getId());
		System.out.println(hmacHolderArgumentCaptor.getAllValues().get(1).get(0).getCryptoKey().getId());
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(secondHmacKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(secondHmacKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}

	@Test
	@DisplayName("When HMAC keys created date are null, the 1st CryptoKey in the list is used")
	void hmacHmacKeysListCreatedDateNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		CryptoKey secondHmacKey = testCryptoKey();
		secondHmacKey.setId("SecondHmacKeyId");
		testCryptoKey.setCreatedDate(null);
		secondHmacKey.setCreatedDate(null);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey, secondHmacKey));


		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}

	@Test
	void hmacGeneralExceptionFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		RuntimeException thrownException = new RuntimeException();
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willThrow(thrownException);

		assertThatThrownBy(() -> singleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("An error occurred trying to set the HMAC fields:" + thrownException.getClass());
	}

	@Test
	@DisplayName("When multiple HMAC keys exist with created date and start time set to null, use the 1st CryptoKey in the list")
	void allHmacKeysCreatedDateAndStartTimeSetToNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testCryptoKey.setCreatedDate(null);
		testCryptoKey.setKeyStartTime(null);
		CryptoKey inactiveHmacKey = new CryptoKey();
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey, inactiveHmacKey));

		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(testCryptoKey))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}

	@Test
	void allHmacKeysStartTimeSetToFutureTimeFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		CryptoKey inactiveHmacKey = new CryptoKey();
		inactiveHmacKey.setKeyStartTime(Instant.now().plus(Duration.ofDays(2)));
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(inactiveHmacKey, inactiveHmacKey));

		ActiveHmacKeyNotFoundException exception = assertThrows(ActiveHmacKeyNotFoundException.class, () ->
				singleHmacFieldStrategy.hmac(testEntity));
		assertThat(exception.getMessage()).isEqualTo("No active HMAC key was found");
	}

	@Test
	@DisplayName("When multiple HMAC keys exist, if the 1st key in the list is has null created date, use the 2nd key if it has a created date")
	void theFirstHmacKeyCreatedDateIsSetToNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testCryptoKey.setCreatedDate(null);
		CryptoKey hmacKeyWithCreatedDate = testCryptoKey();
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey, hmacKeyWithCreatedDate));

		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(hmacKeyWithCreatedDate))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(hmacKeyWithCreatedDate))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}

	@Test
	@DisplayName("When multiple HMAC keys exist, if the 2nd key in the list is has null created date, use the 1st key if it has a created date")
	void theSecondHmacKeyCreatedDateIsSetToNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		CryptoKey hmacKeyWithNullCreatedDate = testCryptoKey();
		hmacKeyWithNullCreatedDate.setCreatedDate(null);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey, hmacKeyWithNullCreatedDate));

		singleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac()).isEqualTo(TEST_USERNAME);

		then(mockEncryptionService).should(times(2)).hmac(hmacHolderArgumentCaptor.capture());
		assertThat(hmacHolderArgumentCaptor.getAllValues()).hasSize(2);
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(0)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(hmacKeyWithNullCreatedDate))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN));
		assertThat(hmacHolderArgumentCaptor.getAllValues().get(1)).hasSize(1)
				.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(hmacKeyWithNullCreatedDate))
				.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
				.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME));
	}
}