package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.TestAnnotatedEntityForSingleHmacFieldStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static ie.bitstep.mango.crypto.testdata.TestData.PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_IDENTITY_CRYPTO_KEY_ID;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.then;

@ExtendWith(MockitoExtension.class)
public class RekeyListHmacStrategyTest {

	private static final String TEST_LOOKUP_FIELD_ALIAS = "lookup fieldAlias";
	private static final String TEST_UNIQUE_VALUES_FIELD_ALIAS = "Unique Values fieldAlias";
	public static final String TEST_SOME_TOKENIZED_VALUE = "Some Tokenized Value";

	private RekeyListHmacFieldStrategy rekeyListHmacFieldStrategy;
	private TestAnnotatedEntityForListHmacFieldStrategy testEntity;
	private List<HmacHolder> newLookupHmacHolders;
	private List<HmacHolder> newUniqueValuesHolders;
	private HmacHolder newLookuphmacHolder;
	private HmacHolder newUniqueValueshmacHolder;

	@Mock
	private ListHmacFieldStrategy mockListHmacStrategy;

	@BeforeEach
	void setup() {
		rekeyListHmacFieldStrategy = new RekeyListHmacFieldStrategy(mockListHmacStrategy, TEST_CRYPTO_KEY);

		testEntity = new TestAnnotatedEntityForListHmacFieldStrategy();
		testEntity.setPan(TEST_PAN);
	}

	@Test
	void getCurrentHmacKeys() {
		assertThat(rekeyListHmacFieldStrategy.getCurrentHmacKeys()).isEqualTo(List.of(TEST_CRYPTO_KEY));
	}

	@Test
	void getDefaultHmacHoldersExistingLookupsNull() throws NoSuchFieldException {
		Field field = testEntity.getClass().getDeclaredField("pan");
		Collection<HmacHolder> defaultHmacHolders = rekeyListHmacFieldStrategy.getDefaultHmacHolders(List.of(TEST_CRYPTO_KEY), field, TEST_PAN, testEntity);
		assertThat(defaultHmacHolders).anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY) && hmacHolder.getHmacAlias().equals(PAN_FIELD_NAME) && hmacHolder.getTokenizedRepresentation() == null && hmacHolder.getValue().equals(TEST_PAN));
	}

	@Test
	void getDefaultHmacHoldersExistingLookupsEmpty() throws NoSuchFieldException {
		testEntity.setLookups(emptyList());
		Field field = testEntity.getClass().getDeclaredField("pan");
		Collection<HmacHolder> defaultHmacHolders = rekeyListHmacFieldStrategy.getDefaultHmacHolders(List.of(TEST_CRYPTO_KEY), field, TEST_PAN, testEntity);
		assertThat(defaultHmacHolders).anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY) && hmacHolder.getHmacAlias().equals(PAN_FIELD_NAME) && hmacHolder.getTokenizedRepresentation() == null && hmacHolder.getValue().equals(TEST_PAN));
	}

	@Test
	void getDefaultHmacHoldersExistingLookupsContainSameHmacKey() throws NoSuchFieldException {
		CryptoShieldHmacHolder existingHmacHolder = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, "Doesn't_Matter");
		testEntity.setLookups(List.of(existingHmacHolder));
		Field field = testEntity.getClass().getDeclaredField("pan");
		Collection<HmacHolder> defaultHmacHolders = rekeyListHmacFieldStrategy.getDefaultHmacHolders(List.of(TEST_CRYPTO_KEY), field, TEST_PAN, testEntity);
		assertThat(defaultHmacHolders).isEmpty();
	}

	@Test
	void getDefaultHmacHoldersExistingLookupsContainOnlyDifferentHmacKey() throws NoSuchFieldException {
		CryptoShieldHmacHolder existingHmacHolder = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, "Doesn't_Matter");
		testEntity.setLookups(List.of(existingHmacHolder));
		Field field = testEntity.getClass().getDeclaredField("pan");
		Collection<HmacHolder> defaultHmacHolders = rekeyListHmacFieldStrategy.getDefaultHmacHolders(List.of(TEST_CRYPTO_KEY), field, TEST_PAN, testEntity);
		assertThat(defaultHmacHolders).anyMatch(hmacHolder -> hmacHolder.getCryptoKey().equals(TEST_CRYPTO_KEY) && hmacHolder.getHmacAlias().equals(PAN_FIELD_NAME) && hmacHolder.getTokenizedRepresentation() == null && hmacHolder.getValue().equals(TEST_PAN));
	}

	@Test
	void preprocessExistingLookupNull() {
		testEntity.setLookups(null);
		testEntity.setUniqueValues(null);
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		HmacHolder newLookuphmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS);
		HmacHolder newUniqueValueshmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		List<HmacHolder> newLookupHmacHolders = new ArrayList<>();
		newLookupHmacHolders.add(newLookuphmacHolder);
		List<HmacHolder> newUniqueValuesHolders = new ArrayList<>();
		newUniqueValuesHolders.add(newUniqueValueshmacHolder);
		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookupHmacHolders, newUniqueValuesHolders);
		assertThat(newLookupHmacHolders).anyMatch(hmacHolder -> hmacHolder.equals(newLookuphmacHolder));
		assertThat(newUniqueValuesHolders).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValueshmacHolder));
	}

	@Test
	void preprocessNotLookupOrUniqueValueImpl() {
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		HmacHolder newLookuphmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS);
		HmacHolder newUniqueValueshmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		List<HmacHolder> newLookupHmacHolders = new ArrayList<>();
		newLookupHmacHolders.add(newLookuphmacHolder);
		List<HmacHolder> newUniqueValuesHolders = new ArrayList<>();
		newUniqueValuesHolders.add(newUniqueValueshmacHolder);
		TestAnnotatedEntityForSingleHmacFieldStrategy testEntity = new TestAnnotatedEntityForSingleHmacFieldStrategy();

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookupHmacHolders, newUniqueValuesHolders);
		assertThat(newLookupHmacHolders).anyMatch(hmacHolder -> hmacHolder.equals(newLookuphmacHolder));
		assertThat(newUniqueValuesHolders).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValueshmacHolder));
	}

	@Test
	void preprocessExistingLookupUsesDifferentKeySameAliasesNewLookupHasNoTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookuphmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValueshmacHolder = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		List<HmacHolder> newLookupHmacHolders = new ArrayList<>();
		newLookupHmacHolders.add(newLookuphmacHolder);
		List<HmacHolder> newUniqueValuesHolders = new ArrayList<>();
		newUniqueValuesHolders.add(newUniqueValueshmacHolder);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookupHmacHolders, newUniqueValuesHolders);
		assertThat(newLookupHmacHolders).anyMatch(hmacHolder -> hmacHolder.equals(newLookuphmacHolder));
		assertThat(newUniqueValuesHolders).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValueshmacHolder));
	}

	@Test
	void preprocessExistingLookupUsesDifferentKeySameAliasesNewLookupHasTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS, TEST_SOME_TOKENIZED_VALUE);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS, TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void preprocessExistingLookupUsesDifferentKeyDifferentAliasesNewLookupHasNoTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, "Different Alias");
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, "Different Alias");
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void preprocessExistingLookupUsesDifferentKeyDifferentAliasesNewLookupHasTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, "Different Alias", TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_IDENTITY_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, "Different Alias", TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void preprocessExistingLookupUsesSameKeySameAliasesNewLookupHasNoTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS);
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).isEmpty();
		assertThat(newUniqueValues).isEmpty();
	}

	@Test
	void preprocessExistingLookupUsesSameKeySameAliasesNewLookupHasTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, TEST_LOOKUP_FIELD_ALIAS, TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, TEST_UNIQUE_VALUES_FIELD_ALIAS, TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void preprocessExistingLookupUsesSameKeyDifferentAliasesNewLookupHasNoTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, "Different Alias");
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, "Different Alias");
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);

		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void preprocessExistingLookupUsesSameKeyDifferentAliasesNewLookupHasTokenizedValue() {
		String someExistingHmacValue = "Value calculated with existing HMAC key";
		String plainTextLookupSourceValue = "Plain text source Value for lookup";
		String plainTextUniqueValueSourceValue = "Plain text source Value for unique value";
		CryptoShieldHmacHolder existingLookups = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_LOOKUP_FIELD_ALIAS);
		testEntity.setLookups(List.of(existingLookups)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newLookup = new HmacHolder(TEST_CRYPTO_KEY, plainTextLookupSourceValue, "Different Alias", TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newLookups = new ArrayList<>();
		newLookups.add(newLookup);
		CryptoShieldHmacHolder existingUniqueValues = new CryptoShieldHmacHolder(TEST_CRYPTO_KEY_ID, someExistingHmacValue, TEST_UNIQUE_VALUES_FIELD_ALIAS);
		testEntity.setUniqueValues(List.of(existingUniqueValues)); // unmodifiable list so if it's messed with this test will blow up and we'll know
		HmacHolder newUniqueValue = new HmacHolder(TEST_CRYPTO_KEY, plainTextUniqueValueSourceValue, "Different Alias", TEST_SOME_TOKENIZED_VALUE);
		List<HmacHolder> newUniqueValues = new ArrayList<>();
		newUniqueValues.add(newUniqueValue);

		rekeyListHmacFieldStrategy.preProcessForRekey(testEntity, newLookups, newUniqueValues);
		assertThat(newLookups).anyMatch(hmacHolder -> hmacHolder.equals(newLookup));
		assertThat(newUniqueValues).anyMatch(hmacHolder -> hmacHolder.equals(newUniqueValue));
	}

	@Test
	void hmac() {
		rekeyListHmacFieldStrategy.hmac(testEntity);

		then(mockListHmacStrategy).should().hmac(testEntity, rekeyListHmacFieldStrategy);
	}
}