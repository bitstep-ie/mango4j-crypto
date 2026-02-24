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
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac1TargetField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac2TargetField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNonTransientHmacField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityDoubleHmacStrategyNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyInvalidHmacKeyIdFieldKeyNumber;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyMissingHmacKeyIdFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyOnlyOneHmacKeyIdField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyWithHmacKeyIdFieldsReversed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.testdata.TestData.ENTITY_HMAC_FIELDS_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_2;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ETHNICITY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_FAVOURITE_COLOR;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USERNAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.times;

@ExtendWith(MockitoExtension.class)
class DoubleHmacFieldStrategyTest {

	private DoubleHmacFieldStrategy doubleHmacFieldStrategy;

	@Mock
	private HmacStrategyHelper mockHmacHelper;

	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	@Mock
	private EncryptionService mockEncryptionService;

	@Mock
	private CryptoKey newCryptoKey;

	@Mock
	private CryptoKey oldCryptoKey;

	private TestAnnotatedEntityForDoubleHmacFieldStrategy testEntity;

	@BeforeEach
	void setup() {
		testEntity = new TestAnnotatedEntityForDoubleHmacFieldStrategy();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);

		doubleHmacFieldStrategy = new DoubleHmacFieldStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategy.class, mockHmacHelper);
	}

	@Test
	void registerSuccess() throws NoSuchFieldException, IllegalAccessException {
		Map<Field, List<Field>> entityHmacFields = getEntityHmacFieldsMap();
		List<Field> actualPanTargetHmacFields = entityHmacFields.get(TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("pan"));
		Field expectedTargetPanHmac1Field = actualPanTargetHmacFields.get(0);
		expectedTargetPanHmac1Field.setAccessible(true);
		Field targetPanHmac1Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("panHmac1");
		targetPanHmac1Field.setAccessible(true);
		assertThat(expectedTargetPanHmac1Field).isEqualTo(targetPanHmac1Field);

		Field expectedTargetPanHmac2Field = actualPanTargetHmacFields.get(1);
		expectedTargetPanHmac2Field.setAccessible(true);
		Field targetPanHmac2Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("panHmac2");
		targetPanHmac2Field.setAccessible(true);
		assertThat(expectedTargetPanHmac2Field).isEqualTo(targetPanHmac2Field);

		List<Field> actualUserNameTargetHmacFields = entityHmacFields.get(TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("userName"));
		Field expectedTargetUserName1Field = actualUserNameTargetHmacFields.get(0);
		expectedTargetUserName1Field.setAccessible(true);
		Field targetUserName1Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("userNameHmac1");
		targetUserName1Field.setAccessible(true);

		Field expectedTargetUserName2Field = actualUserNameTargetHmacFields.get(1);
		expectedTargetUserName2Field.setAccessible(true);
		Field targetUserName2Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("userNameHmac2");
		targetUserName2Field.setAccessible(true);


		List<Field> actualSomeOtherHmacValueTargetHmacFields = entityHmacFields.get(TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("someOtherHmacValue"));
		Field expectedTargetSomeOtherHmacValue1Field = actualSomeOtherHmacValueTargetHmacFields.get(0);
		expectedTargetSomeOtherHmacValue1Field.setAccessible(true);
		Field targetSomeOtherHmacValue1Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("someOtherHmacValueHmac1");
		targetSomeOtherHmacValue1Field.setAccessible(true);

		Field expectedTargetSomeOtherHmacValue2Field = actualSomeOtherHmacValueTargetHmacFields.get(1);
		expectedTargetSomeOtherHmacValue2Field.setAccessible(true);
		Field targetSomeOtherHmacValue2Field = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField("someOtherHmacValueHmac2");
		targetSomeOtherHmacValue2Field.setAccessible(true);


		assertThat(expectedTargetPanHmac1Field).isEqualTo(targetPanHmac1Field);
		assertThat(expectedTargetPanHmac2Field).isEqualTo(targetPanHmac2Field);
		assertThat(expectedTargetUserName1Field).isEqualTo(targetUserName1Field);
		assertThat(expectedTargetUserName2Field).isEqualTo(targetUserName2Field);
		assertThat(expectedTargetSomeOtherHmacValue1Field).isEqualTo(targetSomeOtherHmacValue1Field);
		assertThat(expectedTargetSomeOtherHmacValue2Field).isEqualTo(targetSomeOtherHmacValue2Field);
		assertThat(entityHmacFields).hasSize(3);
		assertThat(actualPanTargetHmacFields).hasSize(2);
		assertThat(actualUserNameTargetHmacFields).hasSize(2);
	}

	@Test
	void registerNonTransientHmacFields() {
		NonTransientCryptoException nonTransientCryptoException = assertThrows(NonTransientCryptoException.class,
				() -> new DoubleHmacFieldStrategy(InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNonTransientHmacField.class, mockHmacHelper));

		assertThat(nonTransientCryptoException).hasMessage("InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNonTransientHmacField has a field named pan marked with @Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@Test
	void registerHmacSourceFieldsWithoutCorrespondingHmac1TargetField() {
		assertThatThrownBy(() -> new DoubleHmacFieldStrategy(InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac1TargetField.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'pan' does not have an associated field called 'panHmac1'");
	}

	@Test
	void registerHmacSourceFieldsWithoutCorrespondingHmac2TargetField() {
		assertThatThrownBy(() -> new DoubleHmacFieldStrategy(InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac2TargetField.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'pan' does not have an associated field called 'panHmac2'");
	}

	@Test
	void registerMissingHmacKeyIdFields() {
		assertThatThrownBy(() -> new DoubleHmacFieldStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategyMissingHmacKeyIdFields.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyMissingHmacKeyIdFields' uses the Double HMAC Strategy but does not have 2 fields annotated with @HmacKeyId. It's mandatory to have 2 String fields annotated with @HmacKeyId when using the Double HMAC Strategy");
	}

	@Test
	void registerOnlyOneHmacKeyIdField() {
		assertThatThrownBy(() -> new DoubleHmacFieldStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategyOnlyOneHmacKeyIdField.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyOnlyOneHmacKeyIdField' uses the Double HMAC Strategy but does not have 2 fields annotated with @HmacKeyId. It's mandatory to have 2 String fields annotated with @HmacKeyId when using the Double HMAC Strategy");
	}

	@Test
	void registerHmacKeyIdFieldsInvalidKeyNumbers() {
		assertThatThrownBy(() -> new DoubleHmacFieldStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategyInvalidHmacKeyIdFieldKeyNumber.class, mockHmacHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'hmacKeyId2' in 'TestAnnotatedEntityForDoubleHmacFieldStrategyInvalidHmacKeyIdFieldKeyNumber' marked with @HmacKeyId but did not have a valid keyNumber value. Entities using the Double HMAC strategy must have keyNumbers from 1 to 2 on the HmacKeyId annotation.");
	}

	@SuppressWarnings("unchecked")
	private Map<Field, List<Field>> getEntityHmacFieldsMap() throws NoSuchFieldException, IllegalAccessException {
		Field entityHmacFieldsField = DoubleHmacFieldStrategy.class
				.getDeclaredField(ENTITY_HMAC_FIELDS_FIELD_NAME);
		entityHmacFieldsField.setAccessible(true);
		return (Map<Field, List<Field>>) entityHmacFieldsField.get(doubleHmacFieldStrategy);
	}

	@Test
	void hmacSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac1()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getPanHmac2()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac1()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getHmacKeyId1()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
	}

	@Test
	void hmacNullValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		testEntity.setPan(null);

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getHmacKeyId1()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
	}

	@Test
	void multipleHmacKeysSuccess() {
		given(oldCryptoKey.getId()).willReturn("HmacKeyId1");
		given(oldCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(0));
		given(newCryptoKey.getId()).willReturn("HmacKeyId2");
		given(newCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(1));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		TEST_CRYPTO_KEY.setCreatedDate(Instant.ofEpochSecond(1000));
		TEST_CRYPTO_KEY_2.setCreatedDate(Instant.ofEpochSecond(2000));
		willAnswer(invocationOnMock -> {
			@SuppressWarnings("unchecked")
			List<HmacHolder> hmacHolders = (List<HmacHolder>) invocationOnMock.getArguments()[0];
			// By convention DoubleHmacStrategy sorts the keys from newest to oldest so the 1st HmacHolder passed to
			// wncryptionService.hmac() will have the new key and the 2nd will have the old key
			hmacHolders.get(0).setValue(hmacHolders.get(0).getValue() + "NewKey");
			hmacHolders.get(1).setValue(hmacHolders.get(1).getValue() + "OldKey");
			return invocationOnMock;
		}).given(mockEncryptionService).hmac(any());
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(oldCryptoKey, newCryptoKey));

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		// HMACs with the old key goes in 1st hmac field and HMACs with the new key goes in 2nd hmac field
		assertThat(testEntity.getPanHmac1()).isEqualTo(TEST_PAN + "OldKey");
		assertThat(testEntity.getPanHmac2()).isEqualTo(TEST_PAN + "NewKey");
		assertThat(testEntity.getUserNameHmac1()).isEqualTo(TEST_USERNAME + "OldKey");
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME + "NewKey");
		assertThat(testEntity.getHmacKeyId1()).isEqualTo(oldCryptoKey.getId());
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(newCryptoKey.getId());

		then(mockEncryptionService).should(times(2)).hmac(any());
		then(mockEncryptionService).should(times(2)).hmac(any());
	}

	@Test
	void multipleHmacKeysSuccessHmacKeyIdFieldsInWrongOrder() {
		TestAnnotatedEntityForDoubleHmacFieldStrategyWithHmacKeyIdFieldsReversed testEntity = new TestAnnotatedEntityForDoubleHmacFieldStrategyWithHmacKeyIdFieldsReversed(); // NOSONAR - reusing testEntity variable name for test
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);

		doubleHmacFieldStrategy = new DoubleHmacFieldStrategy(testEntity.getClass(), mockHmacHelper);

		given(oldCryptoKey.getId()).willReturn("HmacKeyId1");
		given(oldCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(0));
		given(newCryptoKey.getId()).willReturn("HmacKeyId2");
		given(newCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(1));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		TEST_CRYPTO_KEY.setCreatedDate(Instant.ofEpochSecond(1000));
		TEST_CRYPTO_KEY_2.setCreatedDate(Instant.ofEpochSecond(2000));
		willAnswer(invocationOnMock -> {
			@SuppressWarnings("unchecked")
			List<HmacHolder> hmacHolders = (List<HmacHolder>) invocationOnMock.getArguments()[0];
			// By convention DoubleHmacStrategy sorts the keys from newest to oldest so the 1st HmacHolder passed to
			// wncryptionService.hmac() will have the new key and the 2nd will have the old key
			hmacHolders.get(0).setValue(hmacHolders.get(0).getValue() + "NewKey");
			hmacHolders.get(1).setValue(hmacHolders.get(1).getValue() + "OldKey");
			return invocationOnMock;
		}).given(mockEncryptionService).hmac(any());
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(oldCryptoKey, newCryptoKey));

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		// HMACs with the old key goes in 1st hmac field and HMACs with the new key goes in 2nd hmac field
		assertThat(testEntity.getPanHmac1()).isEqualTo(TEST_PAN + "OldKey");
		assertThat(testEntity.getPanHmac2()).isEqualTo(TEST_PAN + "NewKey");
		assertThat(testEntity.getUserNameHmac1()).isEqualTo(TEST_USERNAME + "OldKey");
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME + "NewKey");
		assertThat(testEntity.getHmacKeyId1()).isEqualTo(oldCryptoKey.getId());
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(newCryptoKey.getId());

		then(mockEncryptionService).should(times(2)).hmac(any());
		then(mockEncryptionService).should(times(2)).hmac(any());
	}

	@Test
	void hmacUnsupportedKeyTypeFailure() {
		CryptoKey unsupportedHmacKey = new CryptoKey();
		unsupportedHmacKey.setType("UNSUPPORTED");
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(unsupportedHmacKey));
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		willThrow(new UnsupportedKeyTypeException(TEST_CRYPTO_KEY)).given(mockEncryptionService).hmac(any());

		UnsupportedKeyTypeException exception = assertThrows(UnsupportedKeyTypeException.class, () ->
				doubleHmacFieldStrategy.hmac(testEntity));

		assertThat(exception.getMessage()).isEqualTo("No Encryption Service was registered for crypto key [id:TestCryptoKeyId, type:MockTestKey, usage:null]");
	}

	@Test
	void hmacKeyNotActiveKeyFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willThrow(new ActiveHmacKeyNotFoundException());

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity)).isInstanceOf(ActiveHmacKeyNotFoundException.class);
	}

	@Test
	void nullHmacKeysFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(null);

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NoHmacKeysFoundException.class)
				.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void emptyHmacKeysFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NoHmacKeysFoundException.class)
				.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void tooManyHmacKeysFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY_2, TEST_CRYPTO_KEY, TEST_CRYPTO_KEY));

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("More than 2 current HMAC keys were found for entity class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy' and field 'pan'. This strategy only supports up to 2 HMAC keys.");
	}

	@Test
	void hmacKeyGeneralExceptionFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willThrow(new RuntimeException("Test Message"));

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(RuntimeException.class)
				.hasMessage("An error occurred trying to set the HMAC fields:class java.lang.RuntimeException");
	}

	@Test
	void hmacNoHmacFields() {
		doubleHmacFieldStrategy = new DoubleHmacFieldStrategy(TestAnnotatedEntityDoubleHmacStrategyNoHmacFields.class, mockHmacHelper);

		assertThatNoException().isThrownBy(() -> doubleHmacFieldStrategy.hmac(new TestAnnotatedEntityNoHmacFields()));
	}

	@SuppressWarnings("unchecked")
	@Test
	void setFieldForOlderHmacKeyGeneralExceptionFailure() throws NoSuchFieldException, IllegalAccessException {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		Field entityHmacKeyIdFieldsField = doubleHmacFieldStrategy.getClass().getDeclaredField("entityHmacKeyIdFields");
		entityHmacKeyIdFieldsField.setAccessible(true);
		List<Field> entityHmacKeyIdFields = (List<Field>) entityHmacKeyIdFieldsField.get(doubleHmacFieldStrategy);
		entityHmacKeyIdFields.set(0, null);
		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(RuntimeException.class)
				.hasMessage("An error occurred trying to set the HMAC field on entity TestAnnotatedEntityForDoubleHmacFieldStrategy: NullPointerException");
	}
}