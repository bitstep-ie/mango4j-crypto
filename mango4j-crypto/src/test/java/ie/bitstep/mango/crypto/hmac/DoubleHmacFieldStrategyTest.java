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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

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
		then(mockCryptoKeyProvider).should(times(1)).getCurrentHmacKeys();
		then(mockEncryptionService).should(times(1)).hmac(any());
	}

	@Test
	void keyIdsAreSetOnceAfterEveryFieldIsProcessed() {
		DoubleHmacFieldStrategyDelegate delegate = mock(DoubleHmacFieldStrategyDelegate.class);
		given(delegate.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setHmacKeyId1("old-1");
		testEntity.setHmacKeyId2("old-2");
		doAnswer(invocation -> {
			assertThat(testEntity.getHmacKeyId1()).isEqualTo("old-1");
			assertThat(testEntity.getHmacKeyId2()).isEqualTo("old-2");
			return null;
		}).when(delegate).setFieldForOlderHmacKey(any(), any(), any());

		doubleHmacFieldStrategy.hmac(testEntity, delegate);

		then(delegate).should(times(2)).setFieldForOlderHmacKey(any(), any(), any());
		then(delegate).should(times(1)).setOlderHmacKeyId(testEntity, List.of(TEST_CRYPTO_KEY));
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
	}

	@Test
	void nullValuesSkipHolderProcessingButStillSetKeyIds() {
		DoubleHmacFieldStrategyDelegate delegate = mock(DoubleHmacFieldStrategyDelegate.class);
		given(delegate.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		testEntity.setPan(null);
		testEntity.setUserName("");
		testEntity.setPanHmac1("stale");
		testEntity.setPanHmac2("stale");

		doubleHmacFieldStrategy.hmac(testEntity, delegate);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
		then(delegate).should().getCurrentHmacKeys();
		then(delegate).should().setOlderHmacKeyId(testEntity, List.of(TEST_CRYPTO_KEY));
		then(delegate).shouldHaveNoMoreInteractions();
	}

	@Test
	void fieldCalculationFailureDoesNotUpdateKeyIds() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setHmacKeyId1("old-1");
		testEntity.setHmacKeyId2("old-2");
		testEntity.setPan(null);
		testEntity.setPanHmac1("old-pan");
		testEntity.setUserNameHmac2("old-name");
		willAnswer(invocation -> {
			throw new NonTransientCryptoException("HMAC failed");
		}).given(mockEncryptionService).hmac(any());

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NonTransientCryptoException.class);
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old-1");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo("old-2");
		assertThat(testEntity.getPanHmac1()).isEqualTo("old-pan");
		assertThat(testEntity.getUserNameHmac2()).isEqualTo("old-name");
	}

	@Test
	void mixedNullAndNonNullValuesUseOneBatchWithOnlyNonNullHolders() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		given(oldCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(1));
		given(newCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(2));
		given(oldCryptoKey.getId()).willReturn("old");
		given(newCryptoKey.getId()).willReturn("new");
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(oldCryptoKey, newCryptoKey));
		testEntity.setPan("");
		testEntity.setPanHmac1("stale");
		testEntity.setPanHmac2("stale");
		willAnswer(invocation -> {
			List<HmacHolder> holders = invocation.getArgument(0);
			assertThat(holders).hasSize(2).allMatch(holder -> holder.getValue().equals(TEST_USERNAME)
					&& holder.getHmacAlias().equals("userName"));
			holders.forEach(holder -> holder.setValue(holder.getCryptoKey().getId() + ":" + holder.getValue()));
			return null;
		}).given(mockEncryptionService).hmac(any());

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isEqualTo("old:" + TEST_USERNAME);
		assertThat(testEntity.getUserNameHmac2()).isEqualTo("new:" + TEST_USERNAME);
		then(mockEncryptionService).should(times(1)).hmac(any());
	}

	@Test
	void rekeyBatchesAllNonNullSourcesAndKeepsOlderValues() {
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setPanHmac1("old-pan");
		testEntity.setUserNameHmac1("old-name");
		testEntity.setHmacKeyId1("old-key");
		willAnswer(invocation -> {
			List<HmacHolder> holders = invocation.getArgument(0);
			assertThat(holders).hasSize(2).extracting(HmacHolder::getHmacAlias)
					.containsExactlyInAnyOrder("pan", "userName");
			holders.forEach(holder -> holder.setValue("target:" + holder.getValue()));
			return null;
		}).given(mockEncryptionService).hmac(any());

		new RekeyDoubleHmacFieldStrategy(doubleHmacFieldStrategy, TEST_CRYPTO_KEY).hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isEqualTo("old-pan");
		assertThat(testEntity.getUserNameHmac1()).isEqualTo("old-name");
		assertThat(testEntity.getPanHmac2()).isEqualTo("target:" + TEST_PAN);
		assertThat(testEntity.getUserNameHmac2()).isEqualTo("target:" + TEST_USERNAME);
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old-key");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
		then(mockEncryptionService).should(times(1)).hmac(any());
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
	}

	@Test
	void hmacNullValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		testEntity.setPan(null);
		testEntity.setPanHmac1("stale-pan-hmac-1");
		testEntity.setPanHmac2("stale-pan-hmac-2");

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

	@ParameterizedTest
	@NullAndEmptySource
	void allEmptyValuesSetBothKeyIdsForSingleKey(String value) {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		testEntity.setPan(value);
		testEntity.setUserName(value);
		testEntity.setPanHmac1("stale");
		testEntity.setPanHmac2("stale");
		testEntity.setUserNameHmac1("stale");
		testEntity.setUserNameHmac2("stale");
		testEntity.setHmacKeyId1("old-1");
		testEntity.setHmacKeyId2("old-2");

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isNull();
		assertThat(testEntity.getUserNameHmac2()).isNull();
		assertThat(testEntity.getHmacKeyId1()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
		then(mockEncryptionService).shouldHaveNoInteractions();
	}

	@ParameterizedTest
	@NullAndEmptySource
	void allEmptyValuesSetOldAndNewKeyIds(String value) {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(oldCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(1));
		given(newCryptoKey.getCreatedDate()).willReturn(Instant.ofEpochSecond(2));
		given(oldCryptoKey.getId()).willReturn("old");
		given(newCryptoKey.getId()).willReturn("new");
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(newCryptoKey, oldCryptoKey));
		testEntity.setPan(value);
		testEntity.setUserName(value);
		testEntity.setHmacKeyId1("stale");
		testEntity.setHmacKeyId2("stale");

		doubleHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isNull();
		assertThat(testEntity.getUserNameHmac2()).isNull();
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo("new");
		then(mockEncryptionService).shouldHaveNoInteractions();
	}

	@ParameterizedTest
	@NullAndEmptySource
	void rekeyAllEmptyValuesUpdatesOnlyNewKeyId(String value) {
		testEntity.setPan(value);
		testEntity.setUserName(value);
		testEntity.setPanHmac1("stale");
		testEntity.setPanHmac2("stale");
		testEntity.setUserNameHmac1("stale");
		testEntity.setUserNameHmac2("stale");
		testEntity.setHmacKeyId1("old-key");
		testEntity.setHmacKeyId2("stale-key");

		new RekeyDoubleHmacFieldStrategy(doubleHmacFieldStrategy, TEST_CRYPTO_KEY).hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isNull();
		assertThat(testEntity.getUserNameHmac2()).isNull();
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old-key");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
		then(mockEncryptionService).shouldHaveNoInteractions();
	}

	@Test
	void rekeyMixedValuesKeepsOlderNonNullHmacAndUpdatesTargetKeyId() {
		given(mockHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		testEntity.setPan(null);
		testEntity.setPanHmac1("stale-pan");
		testEntity.setPanHmac2("stale-pan");
		testEntity.setUserNameHmac1("old-name-hmac");
		testEntity.setUserNameHmac2("stale-name-hmac");
		testEntity.setHmacKeyId1("old-key");
		testEntity.setHmacKeyId2("stale-key");

		new RekeyDoubleHmacFieldStrategy(doubleHmacFieldStrategy, TEST_CRYPTO_KEY).hmac(testEntity);

		assertThat(testEntity.getPanHmac1()).isNull();
		assertThat(testEntity.getPanHmac2()).isNull();
		assertThat(testEntity.getUserNameHmac1()).isEqualTo("old-name-hmac");
		assertThat(testEntity.getUserNameHmac2()).isEqualTo(TEST_USERNAME);
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old-key");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo(TEST_CRYPTO_KEY_ID);
		then(mockEncryptionService).should(times(1)).hmac(any());
		then(mockCryptoKeyProvider).shouldHaveNoInteractions();
	}

	@Test
	void allNullValuesWithoutKeysFailsWithoutChangingFields() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());
		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setPanHmac1("stale");
		testEntity.setHmacKeyId1("old");
		testEntity.setHmacKeyId2("old");

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity)).isInstanceOf(NoHmacKeysFoundException.class);

		assertThat(testEntity.getPanHmac1()).isEqualTo("stale");
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo("old");
		then(mockEncryptionService).shouldHaveNoInteractions();
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
			assertThat(hmacHolders).hasSize(4);
			assertThat(hmacHolders).extracting(HmacHolder::getHmacAlias)
					.containsExactlyInAnyOrder("pan", "pan", "userName", "userName");
			assertThat(hmacHolders).allMatch(holder -> holder.getValue() != null);
			hmacHolders.forEach(holder -> holder.setValue(holder.getValue()
					+ (holder.getCryptoKey() == newCryptoKey ? "NewKey" : "OldKey")));
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

		then(mockEncryptionService).should(times(1)).hmac(any());
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
			assertThat(hmacHolders).hasSize(4);
			hmacHolders.forEach(holder -> holder.setValue(holder.getValue()
					+ (holder.getCryptoKey() == newCryptoKey ? "NewKey" : "OldKey")));
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

		then(mockEncryptionService).should(times(1)).hmac(any());
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
	void allNullHmacKeysFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(java.util.Arrays.asList(null, null));

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NoHmacKeysFoundException.class)
				.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void tooManyHmacKeysFailure() {
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY_2, TEST_CRYPTO_KEY, TEST_CRYPTO_KEY));
		testEntity.setPanHmac1("unchanged");
		testEntity.setHmacKeyId1("old");
		testEntity.setHmacKeyId2("old");

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessageContaining("More than 2 current HMAC keys were found for entity class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy'")
				.hasMessageContaining("This strategy only supports up to 2 HMAC keys.");
		assertThat(testEntity.getPanHmac1()).isEqualTo("unchanged");
		assertThat(testEntity.getHmacKeyId1()).isEqualTo("old");
		assertThat(testEntity.getHmacKeyId2()).isEqualTo("old");
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
	void hmacNoHmacFieldsStillValidatesKeys() {
		doubleHmacFieldStrategy = new DoubleHmacFieldStrategy(TestAnnotatedEntityDoubleHmacStrategyNoHmacFields.class, mockHmacHelper);
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());

		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(new TestAnnotatedEntityNoHmacFields()))
				.isInstanceOf(NoHmacKeysFoundException.class);
	}

	@SuppressWarnings("unchecked")
	@Test
	void setFieldForOlderHmacKeyGeneralExceptionFailure() throws NoSuchFieldException, IllegalAccessException {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		testEntity.setPan(null);
		testEntity.setUserName(null);

		Field entityHmacKeyIdFieldsField = doubleHmacFieldStrategy.getClass().getDeclaredField("entityHmacKeyIdFields");
		entityHmacKeyIdFieldsField.setAccessible(true);
		List<Field> entityHmacKeyIdFields = (List<Field>) entityHmacKeyIdFieldsField.get(doubleHmacFieldStrategy);
		entityHmacKeyIdFields.set(0, null);
		assertThatThrownBy(() -> doubleHmacFieldStrategy.hmac(testEntity))
				.isInstanceOf(RuntimeException.class)
				.hasMessage("An error occurred trying to set the HMAC field on entity TestAnnotatedEntityForDoubleHmacFieldStrategy: NullPointerException");
	}
}