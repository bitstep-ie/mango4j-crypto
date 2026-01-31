package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.exceptions.NoHmacKeysFoundException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.exceptions.HmacTokenizerInstantiationException;
import ie.bitstep.mango.crypto.exceptions.InvalidUniqueGroupDefinition;
import ie.bitstep.mango.crypto.exceptions.NoHmacFieldsFoundException;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyLookupFieldWithoutLookupImplementation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyLookupImplementationWithoutLookupField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyUniqueFieldWithoutUniqueImplementation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyUniqueImplementationWithoutUniqueField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithClearTextOnlyUniqueGroup;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNonHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacUniqueGroupAndLookup;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithOnlyLookups;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithOnlyUniqueValues;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithUniqueGroupWithInvalidOrdering;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityWithInvalidHmacTokenizerForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.implementations.tokenizers.TestHmacTokenizer;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ie.bitstep.mango.crypto.testdata.TestData.ENTITY_HMAC_FIELDS_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.ENTITY_HMAC_TOKENIZERS_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_2;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_FAVOURITE_COLOR;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_IDENTITY_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USERNAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USER_NAME_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.implementations.tokenizers.TestHmacTokenizer.TOKENIZED_ALIAS_SUFFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
class ListHmacFieldStrategyTest {

	private static final String TEST_ETHNICITY = "Vulcan";
	private static final String TEST_ALIAS = "TestAlias";

	private ListHmacFieldStrategy listHmacFieldStrategy;

	@Mock
	private HmacStrategyHelper mockStrategyHmacHelper;

	@Mock
	private CryptoKeyProvider mockCryptoKeyProvider;

	@Mock
	private EncryptionService mockEncryptionService;

	@Mock
	private ListHmacFieldStrategyDelegate mockListHmacFieldStrategyDelegate;

	@Captor
	private ArgumentCaptor<Collection<HmacHolder>> cryptoShieldHmacHolderArgumentCaptor;

	private TestAnnotatedEntityForListHmacFieldStrategy annotatedEntityForListHmacFieldStrategy;

	@BeforeEach
	void setup() {
		annotatedEntityForListHmacFieldStrategy = new TestAnnotatedEntityForListHmacFieldStrategy();
		annotatedEntityForListHmacFieldStrategy.setEthnicity(TEST_ETHNICITY);
		annotatedEntityForListHmacFieldStrategy.setFavouriteColor(TEST_FAVOURITE_COLOR);
		annotatedEntityForListHmacFieldStrategy.setPan(TEST_PAN);
		annotatedEntityForListHmacFieldStrategy.setUserName(TEST_USERNAME);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategy.class, mockStrategyHmacHelper);
	}

	@Test
	void constructorSuccess() throws NoSuchFieldException, IllegalAccessException {
		Map<Field, Hmac> entityHmacFields = getEntityHmacFieldsMap();
		Hmac.Purposes[] expectedPanPurposes = entityHmacFields.get(TestAnnotatedEntityForListHmacFieldStrategy.class.getDeclaredField("pan")).purposes();
		assertThat(expectedPanPurposes).contains(Hmac.Purposes.LOOKUP).doesNotContain(Hmac.Purposes.UNIQUE);

		Hmac.Purposes[] expectedUserNamePurposes = entityHmacFields.get(TestAnnotatedEntityForListHmacFieldStrategy.class.getDeclaredField("userName")).purposes();
		assertThat(expectedUserNamePurposes).contains(Hmac.Purposes.LOOKUP).contains(Hmac.Purposes.UNIQUE);
		assertThat(getEntityUniqueGroups().isEmpty()).isTrue();
	}

	@Test
	void constructorWithTokenizerSuccess() throws NoSuchFieldException, IllegalAccessException {
		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class, mockStrategyHmacHelper);

		Map<Field, Hmac> entityHmacFields = getEntityHmacFieldsMap();
		Hmac.Purposes[] expectedPanPurposes = entityHmacFields.get(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class.getDeclaredField("pan")).purposes();
		assertThat(expectedPanPurposes).contains(Hmac.Purposes.LOOKUP).doesNotContain(Hmac.Purposes.UNIQUE);

		Hmac.Purposes[] expectedUserNamePurposes = entityHmacFields.get(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class.getDeclaredField("userName")).purposes();
		assertThat(expectedUserNamePurposes).contains(Hmac.Purposes.LOOKUP).contains(Hmac.Purposes.UNIQUE);

		Map<Field, Set<HmacTokenizer>> entityHmacTokenizers = getEntityHmacTokenizersMap();
		Set<HmacTokenizer> panHmacTokenizers = entityHmacTokenizers.get(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class.getDeclaredField("pan"));
		assertThat(panHmacTokenizers).hasSize(1);
		assertThat(panHmacTokenizers.iterator().next()).isInstanceOf(TestHmacTokenizer.class);
		Set<HmacTokenizer> userNameHmacTokenizers = entityHmacTokenizers.get(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class.getDeclaredField("userName"));
		assertThat(userNameHmacTokenizers).isNull();
		assertThat(getEntityUniqueGroups().isEmpty()).isTrue();
	}

	@Test
	void constructorWithUniqueGroupNoOtherStandaloneHmacs() throws NoSuchFieldException, IllegalAccessException {
		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.class, mockStrategyHmacHelper);

		assertThat(getEntityHmacFieldsMap()).isEmpty();
		assertThat(getEntityUniqueGroups().getGroups().get(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME).getAllFields()).hasSize(2);
	}

	@Test
	void constructorWithTokenizerNoDefaultConstructorFailure() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(TestAnnotatedEntityWithInvalidHmacTokenizerForListHmacFieldStrategy.class, mockStrategyHmacHelper))
			.isInstanceOf(HmacTokenizerInstantiationException.class)
			.hasMessage("Could not create an instance of HmacTokenizer type TestInvalidHmacTokenizerNoDefaultConstructor. Please make sure that TestInvalidHmacTokenizerNoDefaultConstructor has a default no-args constructor declared");
	}

	@Test
	void constructorNonTransientHmacFields() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField has a field named pan marked with @Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@Test
	void constructorUniqueGroupFieldButNoUniquePurpose() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose has a HMAC field named pan marked with @UniqueGroup with but it does not have a purpose of UNIQUE");
	}

	@Test
	void constructorNonStringHmacFields() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField has a field named pan marked with @Hmac but it is of type of int. HMAC fields can only be of type String");
	}

	@Test
	void constructorLookupHmacFieldWithoutLookupImplementation() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyLookupFieldWithoutLookupImplementation.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyLookupFieldWithoutLookupImplementation has at least one field marked with @Hmac with Purposes containing LOOKUP but this class does not implement Lookup. Please make InvalidAnnotatedEntityForListHmacFieldStrategyLookupFieldWithoutLookupImplementation implements the Lookup interface if you want this entity class to use the ListHmacFieldStrategy strategy");
	}

	@Test
	void constructorUniqueHmacFieldWithoutUniqueImplementation() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyUniqueFieldWithoutUniqueImplementation.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyUniqueFieldWithoutUniqueImplementation has at least one field marked with @Hmac with Purposes containing UNIQUE but this class does not implement Unique. Please make InvalidAnnotatedEntityForListHmacFieldStrategyUniqueFieldWithoutUniqueImplementation implements the Unique interface if you want this entity class to use the ListHmacFieldStrategy strategy");
	}

	@Test
	void constructorLookupImplementationWithoutLookupHmacField() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyLookupImplementationWithoutLookupField.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyLookupImplementationWithoutLookupField implements Lookup but does not have any fields marked with @Hmac with LOOKUP purpose. Please either add a Hmac field with LOOKUP purpose or remove 'implements Lookup' from this class");
	}

	@Test
	void constructorUniqueImplementationWithoutUniqueHmacField() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(InvalidAnnotatedEntityForListHmacFieldStrategyUniqueImplementationWithoutUniqueField.class, mockStrategyHmacHelper))
			.isInstanceOf(NonTransientCryptoException.class)
			.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyUniqueImplementationWithoutUniqueField implements Unique but does not have any fields marked with @Hmac with UNIQUE purpose. Please either add a Hmac field with UNIQUE purpose or remove 'implements Unique' from this class");
	}

	@Test
	void constructorNoHmacFields() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(TestAnnotatedEntityNoHmacFields.class, mockStrategyHmacHelper))
			.isInstanceOf(NoHmacFieldsFoundException.class)
			.hasMessage("Class 'ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields' does not have any fields annotated with Hmac");
	}

	@SuppressWarnings("unchecked")
	private Map<Field, Hmac> getEntityHmacFieldsMap() throws NoSuchFieldException, IllegalAccessException {
		Field entityHmacFieldsField = ListHmacFieldStrategy.class
			.getDeclaredField(ENTITY_HMAC_FIELDS_FIELD_NAME);
		entityHmacFieldsField.setAccessible(true);
		return (Map<Field, Hmac>) entityHmacFieldsField.get(listHmacFieldStrategy);
	}

	@SuppressWarnings("unchecked")
	private Map<Field, Set<HmacTokenizer>> getEntityHmacTokenizersMap() throws NoSuchFieldException, IllegalAccessException {
		Field entityHmacFieldsField = ListHmacFieldStrategy.class
			.getDeclaredField(ENTITY_HMAC_TOKENIZERS_FIELD_NAME);
		entityHmacFieldsField.setAccessible(true);
		return (Map<Field, Set<HmacTokenizer>>) entityHmacFieldsField.get(listHmacFieldStrategy);
	}

	private UniqueGroupSet getEntityUniqueGroups() {
		try {
			Field entityUniqueGroups = listHmacFieldStrategy.getClass().getDeclaredField("entityUniqueGroups");
			entityUniqueGroups.setAccessible(true);
			return ((UniqueGroupSet) entityUniqueGroups.get(listHmacFieldStrategy));
		} catch (Exception e) {
			throw new RuntimeException("Couldn't get entityUniqueGroups field value", e);
		}
	}

	@Test
	void hmacSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacExistingLookupsAndUniqueValuesNotNullSuccess() throws NoSuchFieldException, IllegalAccessException {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		TestAnnotatedEntityForListHmacFieldStrategy entity = new TestAnnotatedEntityForListHmacFieldStrategy();
		entity.setEthnicity(TEST_ETHNICITY);
		entity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);
		Field lookups = entity.getClass().getDeclaredField("lookups");
		lookups.setAccessible(true);
		lookups.set(entity, new ArrayList<>());
		Field uniqueValues = entity.getClass().getDeclaredField("uniqueValues");
		uniqueValues.setAccessible(true);
		uniqueValues.set(entity, new ArrayList<>());

		listHmacFieldStrategy.hmac(entity);

		assertThat(entity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(entity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(entity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = entity.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(entity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacExistingLookupsAndUniqueValuesAlreadyPopulatedWithSameKeySuccess() throws NoSuchFieldException, IllegalAccessException {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		Field lookups = annotatedEntityForListHmacFieldStrategy.getClass().getDeclaredField("lookups");
		lookups.setAccessible(true);
		lookups.set(annotatedEntityForListHmacFieldStrategy, List.of(new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, TEST_ALIAS)));
		Field uniqueValues = annotatedEntityForListHmacFieldStrategy.getClass().getDeclaredField("uniqueValues");
		uniqueValues.setAccessible(true);
		uniqueValues.set(annotatedEntityForListHmacFieldStrategy, List.of(new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, TEST_ALIAS)));

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacExistingLookupsAndUniqueValuesAlreadyPopulatedWithDifferentKeySuccess() throws NoSuchFieldException, IllegalAccessException {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		Field lookups = annotatedEntityForListHmacFieldStrategy.getClass().getDeclaredField("lookups");
		lookups.setAccessible(true);
		String someExistingHmacValue = "SomeExistingHmacValue";
		lookups.set(annotatedEntityForListHmacFieldStrategy, List.of(new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_ALIAS)));
		Field uniqueValues = annotatedEntityForListHmacFieldStrategy.getClass().getDeclaredField("uniqueValues");
		uniqueValues.setAccessible(true);
		uniqueValues.set(annotatedEntityForListHmacFieldStrategy, List.of(new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, TEST_ALIAS)));

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(3);
		CryptoShieldHmacHolder panHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		CryptoShieldHmacHolder existingUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_ALIAS.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(existingUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_IDENTITY_CRYPTO_KEY_ID);
		assertThat(existingUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_ALIAS);
		assertThat(existingUserNameHmacHolder.getValue()).isEqualTo(someExistingHmacValue);

		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(2);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		CryptoShieldHmacHolder existingUniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_ALIAS.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(existingUniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_IDENTITY_CRYPTO_KEY_ID);
		assertThat(existingUniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_ALIAS);
		assertThat(existingUniqueFieldUserNameHmacHolder.getValue()).isEqualTo(someExistingHmacValue);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacWithTokenizerSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy.class, mockStrategyHmacHelper);

		TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy entity = new TestAnnotatedEntityWithHmacTokenizerForListHmacFieldStrategy();
		entity.setEthnicity(TEST_ETHNICITY);
		entity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);

		listHmacFieldStrategy.hmac(entity);

		assertThat(entity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(entity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(entity.getLookups()).hasSize(4);
		CryptoShieldHmacHolder panHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = entity.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(entity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(4)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TOKENIZED_ALIAS_SUFFIX + 1))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME + TOKENIZED_ALIAS_SUFFIX + 1))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TOKENIZED_ALIAS_SUFFIX + 2))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME + TOKENIZED_ALIAS_SUFFIX + 2));
	}

	@Test
	void hmacSuccessLookupsOnly() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithOnlyLookups.class, mockStrategyHmacHelper);

		TestAnnotatedEntityForListHmacFieldStrategyWithOnlyLookups entity = new TestAnnotatedEntityForListHmacFieldStrategyWithOnlyLookups();
		entity.setEthnicity(TEST_ETHNICITY);
		entity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);

		listHmacFieldStrategy.hmac(entity);

		assertThat(entity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(entity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(entity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = entity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));

	}

	@Test
	void hmacSuccessUniqueValuesOnly() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithOnlyUniqueValues.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithOnlyUniqueValues entity = new TestAnnotatedEntityForListHmacFieldStrategyWithOnlyUniqueValues();
		entity.setEthnicity(TEST_ETHNICITY);
		entity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		entity.setPan(TEST_PAN);
		entity.setUserName(TEST_USERNAME);

		listHmacFieldStrategy.hmac(entity);

		assertThat(entity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(entity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(entity.getUniqueValues()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = entity.getUniqueValues().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder userNameHmacHolder = entity.getUniqueValues().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(entity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacMandatoryUniqueValueNull() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategy.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategy testEntity = new TestAnnotatedEntityForListHmacFieldStrategy();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(null);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getUniqueValues()).hasSize(1);
		assertThat(testEntity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder usernameHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(usernameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(usernameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(usernameHmacHolder.getValue()).isNull();

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacMandatoryUniqueValueEmpty() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategy.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategy testEntity = new TestAnnotatedEntityForListHmacFieldStrategy();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName("");

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getUniqueValues()).hasSize(1);
		assertThat(testEntity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder usernameHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(usernameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(usernameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(usernameHmacHolder.getValue()).isNull();

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacSuccessOptionalUniqueValuePopulated() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique testEntity = new TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getUniqueValues()).hasSize(1);
		assertThat(testEntity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder usernameHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(usernameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(usernameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(usernameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME));
	}

	@Test
	void hmacSuccessOptionalUniqueValueNull() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique testEntity = new TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(null);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getUniqueValues()).isNull();
		assertThat(testEntity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder usernameHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(usernameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(usernameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(usernameHmacHolder.getValue()).isNull();

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isZero();

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacSuccessOptionalUniqueValueEmpty() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique testEntity = new TestAnnotatedEntityForListHmacFieldStrategyOptionalUnique();
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName("");

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(testEntity.getUniqueValues()).isNull();
		assertThat(testEntity.getLookups()).hasSize(2);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		CryptoShieldHmacHolder usernameHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(usernameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(usernameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(usernameHmacHolder.getValue()).isNull();

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isZero();

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacAllNullFieldValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setPan(null);
		annotatedEntityForListHmacFieldStrategy.setUserName(null);

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());

		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).isEmpty();
	}

	@Test
	void hmacAllEmptyFieldValuesSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setPan("");
		annotatedEntityForListHmacFieldStrategy.setUserName("");

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());

		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).isEmpty();
	}

	@Test
	void hmacNullLookupFieldValueSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setPan(null);

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		CryptoShieldHmacHolder panHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isNull();

		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME));
	}

	@Test
	void hmacEmptyLookupFieldValueSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setPan("");

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		CryptoShieldHmacHolder panHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isNull();

		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getUniqueValues().stream()
			.filter(hmacHolder -> TEST_USER_NAME_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TEST_USER_NAME_FIELD_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_USERNAME);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_USER_NAME_FIELD_NAME));
	}

	@Test
	void hmacNullUniqueValueFieldValueSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setUserName(null);

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_PAN);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacEmptyUniqueValueFieldValueSuccess() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		annotatedEntityForListHmacFieldStrategy.setUserName("");

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);

		CryptoShieldHmacHolder userNameHmacHolder = annotatedEntityForListHmacFieldStrategy.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(userNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(userNameHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(userNameHmacHolder.getValue()).isEqualTo(TEST_PAN);

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacNoKeysFoundFailure() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of());

		assertThatThrownBy(() -> listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy))
			.isInstanceOf(NoHmacKeysFoundException.class)
			.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void hmacKeysNullFailure() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(null);

		assertThatThrownBy(() -> listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy))
			.isInstanceOf(NoHmacKeysFoundException.class)
			.hasMessage("No HMAC CryptoKeys were found");
	}

	@Test
	void hmacSuccessListHmacFieldStrategyDelegate() {
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);
		// make the delegate return a different crypto key
		List<CryptoKey> mockListHmacFieldStrategyDelegateCryptoKeys = List.of(TEST_CRYPTO_KEY_2);
		given(mockListHmacFieldStrategyDelegate.getCurrentHmacKeys()).willReturn(mockListHmacFieldStrategyDelegateCryptoKeys);
		String testValue = "TestValue";
		String testAlias = "testAlias";
		given(mockListHmacFieldStrategyDelegate.getDefaultHmacHolders(eq(mockListHmacFieldStrategyDelegateCryptoKeys), any(), eq(TEST_PAN), eq(annotatedEntityForListHmacFieldStrategy)))
			.willReturn(List.of(new HmacHolder(TEST_CRYPTO_KEY_2, testValue, testAlias)));
		given(mockListHmacFieldStrategyDelegate.getDefaultHmacHolders(eq(mockListHmacFieldStrategyDelegateCryptoKeys), any(), eq(TEST_USERNAME), eq(annotatedEntityForListHmacFieldStrategy)))
			.willReturn(List.of(new HmacHolder(TEST_CRYPTO_KEY_2, testValue, testAlias)));

		listHmacFieldStrategy.hmac(annotatedEntityForListHmacFieldStrategy, mockListHmacFieldStrategyDelegate);

		assertThat(annotatedEntityForListHmacFieldStrategy.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(annotatedEntityForListHmacFieldStrategy.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);
		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups()).hasSize(2);

		assertThat(annotatedEntityForListHmacFieldStrategy.getLookups())
			.allMatch(cryptoShieldHmacHolder ->
				cryptoShieldHmacHolder.getCryptoKeyId().equals(TEST_IDENTITY_CRYPTO_KEY_ID)
					&& cryptoShieldHmacHolder.getValue().equals(testValue)
					&& cryptoShieldHmacHolder.getHmacAlias().equals(testAlias));


		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues()).hasSize(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getUniqueValues())
			.anyMatch(cryptoShieldHmacHolder ->
				cryptoShieldHmacHolder.getCryptoKeyId().equals(TEST_IDENTITY_CRYPTO_KEY_ID)
					&& cryptoShieldHmacHolder.getValue().equals(testValue)
					&& cryptoShieldHmacHolder.getHmacAlias().equals(testAlias));

		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);
		assertThat(annotatedEntityForListHmacFieldStrategy.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY_2))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(testValue))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(testAlias));

		then(mockListHmacFieldStrategyDelegate).should().preProcessForRekey(eq(annotatedEntityForListHmacFieldStrategy), any(), any());
	}

	@Test
	void hmacUniqueGroupSuccessNoOtherStandaloneHmacs() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = testEntity.getUniqueValues().stream()
			.filter(hmacHolder -> TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_PAN + TEST_USERNAME);

		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME));
	}

	@Test
	void hmacUniqueGroupSuccessOptionalFieldNoOtherStandaloneHmacsAllPopulated() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = testEntity.getUniqueValues().stream()
			.filter(hmacHolder -> TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_PAN + TEST_USERNAME);

		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME));
	}

	@Test
	void hmacUniqueGroupSuccessPanOptionalFieldNoOtherStandaloneHmacsNullPan() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional();
		testEntity.setPan(null);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).isNull();
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isZero();

		then(mockEncryptionService).shouldHaveNoMoreInteractions();
	}

	@Test
	void hmacUniqueGroupSuccessPanMandatoryFieldNoOtherStandaloneHmacsNullUsername() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(null);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = testEntity.getUniqueValues().stream()
			.filter(hmacHolder -> TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_PAN + "null");

		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + "null"))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME));
	}

	@Test
	void hmacUniqueGroupSuccessPanOptionalFieldNoOtherStandaloneHmacsEmptyPan() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional();
		testEntity.setPan("");
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).isNull();
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isZero();

		then(mockEncryptionService).shouldHaveNoMoreInteractions();
	}

	@Test
	void hmacUniqueGroupSuccessPanOptionalFieldNoOtherStandaloneHmacsNullPanAndUsername() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupPanOptional();
		testEntity.setPan(null);
		testEntity.setUserName(null);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).isNull();
		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isZero();

		then(mockEncryptionService).shouldHaveNoMoreInteractions();
	}

	@Test
	void hmacUniqueGroupWithNonHmacFieldsSuccessNoOtherStandaloneHmacs() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNonHmacFields.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNonHmacFields testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNonHmacFields();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = testEntity.getUniqueValues().stream()
			.filter(hmacHolder -> TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_PAN + TEST_USERNAME + TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(1)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TEST_USERNAME + TEST_FAVOURITE_COLOR))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME));
	}

	@Test
	void hmacUniqueGroupSuccessWithStandaloneLookupHmac() {
		given(mockCryptoKeyProvider.getCurrentHmacKeys()).willReturn(List.of(TEST_CRYPTO_KEY));
		given(mockStrategyHmacHelper.cryptoKeyProvider()).willReturn(mockCryptoKeyProvider);
		given(mockStrategyHmacHelper.encryptionService()).willReturn(mockEncryptionService);

		listHmacFieldStrategy = new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithHmacUniqueGroupAndLookup.class, mockStrategyHmacHelper);
		TestAnnotatedEntityForListHmacFieldStrategyWithHmacUniqueGroupAndLookup testEntity = new TestAnnotatedEntityForListHmacFieldStrategyWithHmacUniqueGroupAndLookup();
		testEntity.setPan(TEST_PAN);
		testEntity.setUserName(TEST_USERNAME);
		testEntity.setEthnicity(TEST_ETHNICITY);
		testEntity.setFavouriteColor(TEST_FAVOURITE_COLOR);

		listHmacFieldStrategy.hmac(testEntity);

		assertThat(testEntity.getEthnicity()).isEqualTo(TEST_ETHNICITY);
		assertThat(testEntity.getFavouriteColor()).isEqualTo(TEST_FAVOURITE_COLOR);

		assertThat(testEntity.getUniqueValues()).hasSize(1);
		CryptoShieldHmacHolder uniqueFieldUserNameHmacHolder = testEntity.getUniqueValues().stream()
			.filter(hmacHolder -> TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(uniqueFieldUserNameHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(uniqueFieldUserNameHmacHolder.getHmacAlias()).isEqualTo(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME);
		assertThat(uniqueFieldUserNameHmacHolder.getValue()).isEqualTo(TEST_PAN + TEST_USERNAME);

		assertThat(testEntity.getNumberOfTimesAddUniqueValuesWasCalled()).isEqualTo(1);

		assertThat(testEntity.getLookups()).hasSize(1);
		CryptoShieldHmacHolder panHmacHolder = testEntity.getLookups().stream().filter(hmacHolder -> TEST_PAN_FIELD_NAME.equals(hmacHolder.getHmacAlias())).findFirst().orElseThrow();
		assertThat(panHmacHolder.getCryptoKeyId()).isEqualTo(TEST_CRYPTO_KEY_ID);
		assertThat(panHmacHolder.getHmacAlias()).isEqualTo(TEST_PAN_FIELD_NAME);
		assertThat(panHmacHolder.getValue()).isEqualTo(TEST_PAN);

		assertThat(testEntity.getNumberOfTimesAddLookupsWasCalled()).isEqualTo(1);

		then(mockEncryptionService).should().hmac(cryptoShieldHmacHolderArgumentCaptor.capture());
		assertThat(cryptoShieldHmacHolderArgumentCaptor.getValue()).hasSize(2)
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN + TEST_USERNAME))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.TEST_GROUP_NAME))
			.anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY))
			.anyMatch(hmacHolder -> hmacHolder.getValue().equals(TEST_PAN))
			.anyMatch(hmacHolder -> hmacHolder.getHmacAlias().equals(TEST_PAN_FIELD_NAME));
	}

	@Test
	void hmacUniqueGroupWithOnlyClearTextGroupFields() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithClearTextOnlyUniqueGroup.class, mockStrategyHmacHelper))
			.isInstanceOf(InvalidUniqueGroupDefinition.class)
			.hasMessage("There are fields marked with UniqueGroup which only have plain text fields in the group but no corresponding HMAC field as part of the group. Each Unique Group must contain at least one field marked with Hmac");
	}

	@Test
	void hmacUniqueGroupWithInvalidOrdering() {
		assertThatThrownBy(() -> new ListHmacFieldStrategy(TestAnnotatedEntityForListHmacFieldStrategyWithUniqueGroupWithInvalidOrdering.class, mockStrategyHmacHelper))
			.isInstanceOf(InvalidUniqueGroupDefinition.class)
			.hasMessage("The fields in the unique group 'test-group-1' have invalid orderings");
	}
}