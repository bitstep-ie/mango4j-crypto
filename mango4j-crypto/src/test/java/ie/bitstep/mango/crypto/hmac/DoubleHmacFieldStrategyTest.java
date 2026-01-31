package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.exceptions.ActiveHmacKeyNotFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac1TargetField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNoCorrespondingHmac2TargetField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidTestAnnotatedEntityForDoubleHmacFieldStrategyWithNonTransientHmacField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static ie.bitstep.mango.crypto.testdata.TestData.ENTITY_HMAC_FIELDS_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_2;
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
	}

	@Test
	void multipleHmacKeysSuccess() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY_2, TEST_CRYPTO_KEY));

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getPanHmac1()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getPanHmac2()).isEqualTo(TEST_PAN);
		assertThat(testEntity.getUserNameHmac1()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME);

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
	void hmacKeyNotActiveKeySuccess() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willThrow(new ActiveHmacKeyNotFoundException());

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity)).isInstanceOf(ActiveHmacKeyNotFoundException.class);
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
		doubleHmacFieldStrategy = new DoubleHmacFieldStrategy(TestAnnotatedEntityNoHmacFields.class, mockHmacHelper);

		assertThatNoException().isThrownBy(() -> doubleHmacFieldStrategy.hmac(new TestAnnotatedEntityNoHmacFields()));
	}
}