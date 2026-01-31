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
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.TestAnnotatedEntityForSingleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
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

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USER_NAME_FIELD_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willDoNothing;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class SingleHmacFieldStrategyForTimeBasedCryptoKeyTest {

	private static final String TEST_PAN = "5454545454545454";
	private static final String TEST_USERNAME = "username";
	private static final String TEST_FAVOURITE_COLOR = "green";
	private static final String TEST_ETHNICITY = "Vulcan";
	private static final String PAN_HMAC_FIELD_NAME = "panHmac";
	private static final String USER_NAME_HMAC_FIELD_NAME = "userNameHmac";

	private SingleHmacFieldStrategyForTimeBasedCryptoKey singleHmacFieldStrategyForTimeBasedCryptoKey;

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
		testCryptoKey = TestData.testCryptoKey();
		singleHmacFieldStrategyForTimeBasedCryptoKey = new SingleHmacFieldStrategyForTimeBasedCryptoKey(TestAnnotatedEntityForSingleHmacFieldStrategy.class, mockHmacHelper);
		testEntity = new TestAnnotatedEntityForSingleHmacFieldStrategy();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
	}

	@Test
	void registerSuccess() throws NoSuchFieldException, IllegalAccessException {
		singleHmacFieldStrategyForTimeBasedCryptoKey = new SingleHmacFieldStrategyForTimeBasedCryptoKey(TestAnnotatedEntityForSingleHmacFieldStrategy.class, mockHmacHelper);

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
	}

	@Test
	void registerNonTransientHmacFields() {
		NonTransientCryptoException nonTransientCryptoException = assertThrows(NonTransientCryptoException.class, () -> new SingleHmacFieldStrategyForTimeBasedCryptoKey(InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField.class, mockHmacHelper));

		assertThat(nonTransientCryptoException).hasMessage("InvalidAnnotatedEntityForSingleHmacFieldStrategyNonTransientHmacField has a field named userName marked with @Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@SuppressWarnings("unchecked")
	private Map<Field, Field> getEntityHmacFieldsMap() throws NoSuchFieldException, IllegalAccessException {
		Field entityHmacFieldsField = SingleHmacFieldStrategy.class.getDeclaredField(TestData.ENTITY_HMAC_FIELDS_FIELD_NAME);
		entityHmacFieldsField.setAccessible(true);
		return (Map<Field, Field>) entityHmacFieldsField.get(singleHmacFieldStrategyForTimeBasedCryptoKey);
	}

	@Test
	void registerNoHmacFields() {
		assertThatThrownBy(() -> new SingleHmacFieldStrategyForTimeBasedCryptoKey(TestAnnotatedEntityNoHmacFields.class, mockHmacHelper))
				.isInstanceOf(NoHmacFieldsFoundException.class)
				.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields' does not have any fields annotated with Hmac");
	}

	@Test
	void hmacSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity);

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
	void hmacNullValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(testCryptoKey));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		willDoNothing().given(mockEncryptionService).hmac(hmacHolderArgumentCaptor.capture());
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setPan(null);

		singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac()).isNull();
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

		assertThatThrownBy(() -> singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity))
			.isInstanceOf(UnsupportedKeyTypeException.class)
			.hasMessage("No Encryption Service was registered for crypto key [id:TestCryptoKeyId, type:MockTestKey, usage:null]");
	}

	@Test
	void hmacHmacKeysListIsNull() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(null);

		assertThatThrownBy(() -> singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity))
			.isInstanceOf(NoHmacKeysFoundException.class)
			.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void hmacHmacKeysListIsEmpty() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());

		assertThatThrownBy(() -> singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity))
			.isInstanceOf(NoHmacKeysFoundException.class)
			.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void hmacGeneralExceptionFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		RuntimeException thrownException = new RuntimeException();
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willThrow(thrownException);

		assertThatThrownBy(() -> singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("An error occurred trying to set the HMAC fields:" + thrownException.getClass());
	}

	@Test
	void allHmacKeysStartTimeSetToNullFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		CryptoKey inactiveHmacKey = new CryptoKey();
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(inactiveHmacKey, inactiveHmacKey));
		ActiveHmacKeyNotFoundException exception = assertThrows(ActiveHmacKeyNotFoundException.class, () ->
			singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity));
		assertThat(exception.getMessage()).isEqualTo("No active HMAC key was found");
	}

	@Test
	void allHmacKeysStartTimeSetToFutureTimeFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		CryptoKey inactiveHmacKey = new CryptoKey();
		inactiveHmacKey.setKeyStartTime(Instant.now().plus(Duration.ofDays(2)));
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(inactiveHmacKey, inactiveHmacKey));

		ActiveHmacKeyNotFoundException exception = assertThrows(ActiveHmacKeyNotFoundException.class, () ->
			singleHmacFieldStrategyForTimeBasedCryptoKey.hmac(testEntity));
		assertThat(exception.getMessage()).isEqualTo("No active HMAC key was found");
	}
}