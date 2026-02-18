package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.hmac.DoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntityWithNoEncryptFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithBothEncryptHmacAndCascadeEncryptFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveNoOtherAnnotations;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyCascadeEncryptAlso;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyHmac;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestInvalidEntityWithSingleFieldMarkedWithEncryptAndCascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade.TestInvalidEntityWithSingleFieldMarkedWithHmacAndCascadeEncrypt;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidAnnotatedEntityCustomHmacStrategyNoDefaultConstructor;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidAnnotatedEntityMissingHmacStrategyToUseAnnotation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidAnnotatedEntityNoHmacStrategyAnnotation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidAnnotatedEntityNonTransientEncryptField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidEntityWithEnableMigrationSupportAfterDeadline;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.InvalidEntityWithEnableMigrationSupportInvalidDate;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.NothingAnnotatedEntity;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityForExceptionThrowingConstructor;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.ValidEntityWithEnableMigrationSupportBeforeDeadline;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.ValidEntityWithEnableMigrationSupportToday;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptedDataField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.InvalidAnnotatedEntityForDoubleHmacFieldStrategyNonTransientHmacField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyMultipleEncryptionKeyIdAnnotations;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy.TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation;
import ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies.MockHmacStrategyImpl;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ENCRYPTED_DATA_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_ETHNICITY_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_PAN_FIELD_NAME;
import static ie.bitstep.mango.crypto.testdata.TestData.TEST_USER_NAME_FIELD_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class AnnotatedEntityManagerTest {

	@Mock
	private HmacStrategyHelper mockHmacStrategyHelper;

	@SuppressWarnings("OptionalGetWithoutIsPresent")
	@Test
	@DisplayName("Constructor test for entity class with both encrypt and HMAC fields and a derived @HmacStrategyToUse annotation on the entity")
	void constructor() throws NoSuchFieldException, IllegalAccessException {
		Field encryptedDataField = TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField(TEST_ENCRYPTED_DATA_FIELD_NAME);
		TestAnnotatedEntityForDoubleHmacFieldStrategy entity = new TestAnnotatedEntityForDoubleHmacFieldStrategy();
		TestAnnotatedEntityForDoubleHmacFieldStrategy.class.getDeclaredField(TEST_PAN_FIELD_NAME).setAccessible(false);

		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(
				List.of(TestAnnotatedEntityForDoubleHmacFieldStrategy.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.isEqualTo(encryptedDataField);
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.isNotEmpty();

		// Make sure all fields are settable
		for (Field field : annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategy.class)) {
			field.set(entity, TEST_PAN_FIELD_NAME);
		}

		assertThat(annotatedEntityManager.getHmacStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategy.class).get())
				.isInstanceOf(DoubleHmacFieldStrategy.class);

		assertThat(annotatedEntityManager.getAllConfidentialFields(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestAnnotatedEntityForDoubleHmacFieldStrategy.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
	}

	@SuppressWarnings("OptionalGetWithoutIsPresent")
	@Test
	@DisplayName("Constructor test for entity with @HmacStrategyToUse annotation directly on the class")
	void constructorTopLevelHmacStrategyAnnotation() throws NoSuchFieldException, IllegalAccessException {
		Field encryptedDataField = TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class.getDeclaredField(TEST_ENCRYPTED_DATA_FIELD_NAME);
		TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation entity = new TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation();
		TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class.getDeclaredField(TEST_PAN_FIELD_NAME).setAccessible(false);

		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(
				List.of(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class))
				.isEqualTo(encryptedDataField);
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class))
				.isNotEmpty();

		// Make sure all fields are settable
		for (Field field : annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class)) {
			field.set(entity, TEST_PAN_FIELD_NAME);
		}

		assertThat(annotatedEntityManager.getHmacStrategy(TestAnnotatedEntityTopLevelHmacFieldStrategyAnnotation.class).get()).isInstanceOf(DoubleHmacFieldStrategy.class);
	}

	@Test
	@DisplayName("Constructor test for entity with @EncryptionKeyId annotation on a non String field type")
	void constructorNonStringEncryptionKeyIdField() {
		class TestEntityIntEncryptionKeyId {
			@EncryptionKeyId
			private int encryptionKeyId;
		}

		List<Class<?>> annotatedEntityClasses = List.of(TestEntityIntEncryptionKeyId.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("TestEntityIntEncryptionKeyId has a field of type int marked with EncryptionKeyId. Please change this field type to String");
	}

	@SuppressWarnings("OptionalGetWithoutIsPresent")
	@Test
	@DisplayName("Constructor test for entity without an @EncryptionKeyId annotation")
	void constructorNoEncryptionKeyIdAnnotation() throws NoSuchFieldException, IllegalAccessException {
		Field encryptedDataField = TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class.getDeclaredField(TEST_ENCRYPTED_DATA_FIELD_NAME);
		TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation entity = new TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation();
		TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class.getDeclaredField(TEST_PAN_FIELD_NAME).setAccessible(false);

		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(List.of(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class)).isEqualTo(encryptedDataField);

		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class))
				.isNotPresent();

		// Make sure all fields are settable
		for (Field field : annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class)) {
			field.set(entity, TEST_PAN_FIELD_NAME);
		}

		assertThat(annotatedEntityManager.getHmacStrategy(TestAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptionKeyIdAnnotation.class).get()).isInstanceOf(DoubleHmacFieldStrategy.class);
	}

	@Test
	@DisplayName("Constructor test for entity with multiple @EncryptionKeyId annotations")
	void constructorMultipleEncryptionKeyIdAnnotations() {
		List<Class<?>> annotatedEntityClasses = List.of(TestAnnotatedEntityForDoubleHmacFieldStrategyMultipleEncryptionKeyIdAnnotations.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("TestAnnotatedEntityForDoubleHmacFieldStrategyMultipleEncryptionKeyIdAnnotations has more than " +
						"1 field marked with @EncryptionKeyId. Please only annotate a single field with @EncryptionKeyId");
	}

	@Test
	@DisplayName("Constructor test for entity with an @Encrypt field but without a corresponding @EncryptedData field")
	void constructorNoEncryptedBlobFieldForEncryptField() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptedDataField.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("InvalidAnnotatedEntityForDoubleHmacFieldStrategyNoEncryptedDataField has a field marked with @Encrypt but without a " +
						"corresponding field marked with @EncryptedData");
	}

	@Test
	@DisplayName("Constructor test for entity with a non-transient @Encrypt field")
	void constructorNonTransientEncryptField() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityNonTransientEncryptField.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("InvalidAnnotatedEntityNonTransientEncryptField has a field named ethnicity marked with " +
						"@Encrypt but it is not transient. Please mark any fields annotated with @Encrypt as transient");
	}

	@Test
	@DisplayName("Constructor test for entity with a non-transient @Hmac field")
	void constructorNonTransientHmacField() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityForDoubleHmacFieldStrategyNonTransientHmacField.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("InvalidAnnotatedEntityForDoubleHmacFieldStrategyNonTransientHmacField has a field named pan marked with " +
						"@Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@Test
	@DisplayName("Constructor test for a null entity list")
	void constructorNullEntityClassList() {
		assertThatThrownBy(() -> new AnnotatedEntityManager(null, mockHmacStrategyHelper))
				.isInstanceOf(NullPointerException.class)
				.hasMessage("Constructor parameters cannot be null");
	}

	@Test
	@DisplayName("Constructor test for an entity list with a single null element")
	void constructorNullEntityClass() {
		ArrayList<Class<?>> annotatedEntityClasses = new ArrayList<>();
		annotatedEntityClasses.add(null);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NullPointerException.class)
				.hasMessage("Constructor parameters cannot be null");
	}

	@Test
	@DisplayName("Constructor test for an empty entity list")
	void constructorEmptyEntityClassList() {
		List<Class<?>> annotatedEntityClasses = List.of();

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NullPointerException.class)
				.hasMessage("Constructor parameters cannot be null");
	}

	@Test
	@DisplayName("Constructor test for an entity which uses a HmacStrategy whose constructor throws an error on instance creation")
	void constructorHmacStrategyExceptionThrowingConstructor() {
		List<Class<?>> annotatedEntityClasses = List.of(TestAnnotatedEntityForExceptionThrowingConstructor.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Could not create an instance of HmacStrategyExceptionThrowingConstructor class. Please make sure it has a constructor which accepts an HmacStrategyHelper object");
	}

	@Test
	@DisplayName("Constructor test for an entity which has no HMAC fields")
	void constructorNoHmacFields() throws NoSuchFieldException {
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(List.of(TestAnnotatedEntityNoHmacFields.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestAnnotatedEntityNoHmacFields.class)).isEqualTo(TestAnnotatedEntityNoHmacFields.class.getDeclaredField("encryptedData"));
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityNoHmacFields.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityNoHmacFields.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestAnnotatedEntityNoHmacFields.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getHmacStrategy(TestAnnotatedEntityNoHmacFields.class)).isNotPresent();
	}

	@Test
	@DisplayName("Constructor test for an entity which has HMAC fields but no @HmacStrategyToUse defined")
	void constructorNoHmacStrategyAnnotation() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityNoHmacStrategyAnnotation.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("No @HmacStrategyToUse annotation was found on class InvalidAnnotatedEntityNoHmacStrategyAnnotation, " +
						"even though there were fields marked with the @Hmac Annotation. If you want to HMAC some fields make sure " +
						"to add the @HmacStrategyToUse annotation to the InvalidAnnotatedEntityNoHmacStrategyAnnotation class.");
	}

	@Test
	@DisplayName("Constructor test for an entity which uses a HmacStrategy which does not have a constructor which accepts the parameters (Class, HmacStrategyHelper)")
	void constructorNoDefaultConstructor() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityCustomHmacStrategyNoDefaultConstructor.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Could not create an instance of InvalidCustomHmacStrategyNoDefaultConstructor class. Please make sure it has a constructor which accepts an HmacStrategyHelper object");
	}

	@Test
	@DisplayName("Constructor test for an entity which has a derived @HmacStrategyToUse defined incorrectly (missing the @HmacStrategyToUse annotation)")
	void constructorMissingHmacStrategy() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidAnnotatedEntityMissingHmacStrategyToUseAnnotation.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("No @HmacStrategyToUse annotation was found on class InvalidAnnotatedEntityMissingHmacStrategyToUseAnnotation, " +
						"even though there were fields marked with the @Hmac Annotation. If you want to HMAC some fields make sure " +
						"to add the @HmacStrategyToUse annotation to the InvalidAnnotatedEntityMissingHmacStrategyToUseAnnotation class.");
	}

	@Test
	@DisplayName("Constructor test for entity class without any confidential fields")
	void constructorWithNoConfidentialFields() {
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(
				List.of(NothingAnnotatedEntity.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(NothingAnnotatedEntity.class)).isNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(NothingAnnotatedEntity.class)).isEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(NothingAnnotatedEntity.class)).isEmpty();
		assertThat(annotatedEntityManager.getHmacStrategy(NothingAnnotatedEntity.class)).isEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(NothingAnnotatedEntity.class)).isEmpty();
	}

	@Test
	@DisplayName("Constructor test for an entity which has no @Encrypt fields")
	void constructorOnlyHmacFields() {
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(List.of(TestMockHmacEntityWithNoEncryptFields.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestMockHmacEntityWithNoEncryptFields.class)).isNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntityWithNoEncryptFields.class)).isEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestMockHmacEntityWithNoEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestMockHmacEntityWithNoEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getHmacStrategy(TestMockHmacEntityWithNoEncryptFields.class)).isPresent();
	}

	@Test
	@DisplayName("Constructor test for an entity which only has @CascadeEncrypt fields")
	void constructorOnlyCascadeEncryptFields() {
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(List.of(TestMockHmacEntity.class, TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class), mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getEncryptedDataField(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class)).isNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class)).isEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class)).isEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class))
				.isNotPresent();
		assertThat(annotatedEntityManager.getHmacStrategy(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class)).isNotPresent();
		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestMockHmacEntity.class)).isEmpty();

		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class))
				.hasSize(2)
				.filteredOn(field -> field.getName().equals("testMockHmacEntity1")).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class))
				.filteredOn(field -> field.getName().equals("testMockHmacEntity2")).isNotEmpty();

		assertThat(annotatedEntityManager.getEncryptedDataField(TestMockHmacEntity.class)).isNotNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestMockHmacEntity.class))
				.isPresent();
		assertThat(annotatedEntityManager.getHmacStrategy(TestMockHmacEntity.class)).isPresent();
	}

	@Test
	@DisplayName("Constructor test for an entity which has @Encrypt, @Hmac and @CascadeEncrypt fields")
	void constructorBothEncryptAndHmacAndCascadeEncryptFields() {
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(
				List.of(TestMockHmacEntity.class, TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class),
				mockHmacStrategyHelper);

		assertCascadeEncryptFieldsForTestEntityWithBothFields(annotatedEntityManager);
		assertEncryptionFieldsForTestEntityWithBothFields(annotatedEntityManager);
		assertConfidentialFieldsForTestEntityWithBothFields(annotatedEntityManager);
		assertEncryptionConfigForTestEntityWithBothFields(annotatedEntityManager);

		assertEncryptionFieldsForTestMockHmacEntity(annotatedEntityManager);
		assertConfidentialFieldsForTestMockHmacEntity(annotatedEntityManager);
		assertEncryptionConfigForTestMockHmacEntity(annotatedEntityManager);
	}

	private void assertCascadeEncryptFieldsForTestEntityWithBothFields(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestMockHmacEntity.class)).isEmpty();
		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.hasSize(2)
				.filteredOn(field -> field.getName().equals("testMockHmacEntity1")).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToCascadeEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals("testMockHmacEntity2")).isNotEmpty();
	}

	private void assertEncryptionFieldsForTestEntityWithBothFields(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getEncryptedDataField(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class)).isNotNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
	}

	private void assertConfidentialFieldsForTestEntityWithBothFields(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
	}

	private void assertEncryptionConfigForTestEntityWithBothFields(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.isPresent();
		assertThat(annotatedEntityManager.getHmacStrategy(TestEntityWithBothEncryptHmacAndCascadeEncryptFields.class))
				.containsInstanceOf(MockHmacStrategyImpl.class);
	}

	private void assertEncryptionFieldsForTestMockHmacEntity(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getEncryptedDataField(TestMockHmacEntity.class)).isNotNull();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getFieldsToEncrypt(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
	}

	private void assertConfidentialFieldsForTestMockHmacEntity(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_PAN_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_USER_NAME_FIELD_NAME)).isNotEmpty();
		assertThat(annotatedEntityManager.getAllConfidentialFields(TestMockHmacEntity.class))
				.filteredOn(field -> field.getName().equals(TEST_ETHNICITY_FIELD_NAME)).isNotEmpty();
	}

	private void assertEncryptionConfigForTestMockHmacEntity(AnnotatedEntityManager annotatedEntityManager) {
		assertThat(annotatedEntityManager.getEncryptionKeyIdField(TestMockHmacEntity.class))
				.isPresent();
		assertThat(annotatedEntityManager.getHmacStrategy(TestMockHmacEntity.class))
				.containsInstanceOf(MockHmacStrategyImpl.class);
	}

	@Test
	@DisplayName("Constructor test for an invalid entity which has both @Encrypt and @CascadeEncrypt fields")
	void constructorInvalidEntityWithFieldMarkedWithBothEncryptAndCascadeEncrypt() {
		List<Class<?>> annotatedEntityClasses = List.of(TestMockHmacEntity.class, TestInvalidEntityWithSingleFieldMarkedWithEncryptAndCascadeEncrypt.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Fields marked with @CascadeEncrypt cannot also be marked with @Encrypt or @Hmac");
	}

	@Test
	@DisplayName("Constructor test for an invalid entity which has both @Encrypt and @CascadeEncrypt fields")
	void constructorInvalidEntityWithFieldMarkedWithBothHmacAndCascadeEncrypt() {
		List<Class<?>> annotatedEntityClasses = List.of(TestMockHmacEntity.class, TestInvalidEntityWithSingleFieldMarkedWithHmacAndCascadeEncrypt.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Fields marked with @CascadeEncrypt cannot also be marked with @Encrypt or @Hmac");
	}

	@Test
	@DisplayName("Constructor test for a valid entity with a @CascadeEncrypt field but whose type has both @Encrypt and @Hmac but isn't registered")
	void constructorEntityWithFieldMarkedWithCascadeEncryptButNotRegistered() {
		List<Class<?>> annotatedEntityClasses = List.of(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveEncryptAndHmac.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'testMockHmacEntity1' was marked with @CascadeEncrypt but the field type is 'class ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity' which wasn't registered. You'll also need to register this type");
	}

	@Test
	@DisplayName("Constructor test for a valid entity with a @CascadeEncrypt field but whose type only has @Encrypt but isn't registered")
	void constructorEntityWithFieldMarkedWithCascadeEncryptAndWhereTheFieldOnlyHasEncryptButNotRegistered() {
		List<Class<?>> annotatedEntityClasses = List.of(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyEncrypt.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'testAnnotatedEntityNoHmacFields1' was marked with @CascadeEncrypt but the field type is 'class ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom.TestAnnotatedEntityNoHmacFields' which wasn't registered. You'll also need to register this type");
	}

	@Test
	@DisplayName("Constructor test for a valid entity with a @CascadeEncrypt field but whose type only has @Hmac but isn't registered")
	void constructorEntityWithFieldMarkedWithCascadeEncryptAndWhereTheFieldOnlyHasHmacButNotRegistered() {
		List<Class<?>> annotatedEntityClasses = List.of(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyHmac.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'testMockHmacEntityWithNoEncryptFields1' was marked with @CascadeEncrypt but the field type is 'class ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntityWithNoEncryptFields' which wasn't registered. You'll also need to register this type");
	}

	@Test
	@DisplayName("Constructor test for a valid entity with a @CascadeEncrypt field but whose type only has @CascadeEncrypt but isn't registered")
	void constructorEntityWithFieldMarkedWithCascadeEncryptAndWhereTheFieldOnlyHasCascadeEncryptButNotRegistered() {
		List<Class<?>> annotatedEntityClasses = List.of(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveOnlyCascadeEncryptAlso.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'testMockHmacEntity1' was marked with @CascadeEncrypt but the field type is 'class ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity' which wasn't registered. You'll also need to register this type");
	}

	@Test
	@DisplayName("Constructor test for a valid entity with a @CascadeEncrypt field but whose type has no annotations")
	void constructorEntityWithFieldMarkedWithCascadeEncryptAndWhereTheFieldHasNoAnnotations() {
		List<Class<?>> annotatedEntityClasses = List.of(TestEntityWithOnlyCascadeEncryptFieldsWhoseTypesHaveNoOtherAnnotations.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("Field 'nothingAnnotatedEntity1' was marked with @CascadeEncrypt but didn't have @Encrypt or @Hmac fields and also didn't have @CascadeEncrypt fields either. Any fields marked with @CascadeEncrypt must either be encryptable objects or else contain further @CascadeEncrypt fields");
	}

	@Test
	@DisplayName("Constructor test for entity with @EnableMigrationSupport before deadline - should log warning and succeed")
	void constructorWithEnableMigrationSupportBeforeDeadline() {
		List<Class<?>> annotatedEntityClasses = List.of(ValidEntityWithEnableMigrationSupportBeforeDeadline.class);

// Should not throw exception, just log warning
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getFieldsToEncrypt(ValidEntityWithEnableMigrationSupportBeforeDeadline.class))
				.hasSize(1)
				.first()
				.satisfies(field -> assertThat(field.getName()).isEqualTo("email"));
	}

	@Test
	@DisplayName("Constructor test for entity with @EnableMigrationSupport after deadline - should log error but succeed")
	void constructorWithEnableMigrationSupportAfterDeadline() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidEntityWithEnableMigrationSupportAfterDeadline.class);

// Should log ERROR but not throw exception
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getFieldsToEncrypt(InvalidEntityWithEnableMigrationSupportAfterDeadline.class))
				.hasSize(1)
				.first()
				.satisfies(field -> assertThat(field.getName()).isEqualTo("email"));
	}

	@Test
	@DisplayName("Constructor test for entity with @EnableMigrationSupport with invalid date format - should throw exception")
	void constructorWithEnableMigrationSupportInvalidDate() {
		List<Class<?>> annotatedEntityClasses = List.of(InvalidEntityWithEnableMigrationSupportInvalidDate.class);

		assertThatThrownBy(() -> new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessageContaining("Field InvalidEntityWithEnableMigrationSupportInvalidDate.email has @EnableMigrationSupport with invalid completedBy date format 'invalid-date'. Expected format: YYYY-MM-DD");
	}

	@Test
	@DisplayName("Constructor test for entity with @EnableMigrationSupport where deadline is today - should log warning and succeed")
	void constructorWithEnableMigrationSupportToday() {
		List<Class<?>> annotatedEntityClasses = List.of(ValidEntityWithEnableMigrationSupportToday.class);

// Should not throw exception when deadline is today (today is not after today)
		AnnotatedEntityManager annotatedEntityManager = new AnnotatedEntityManager(annotatedEntityClasses, mockHmacStrategyHelper);

		assertThat(annotatedEntityManager.getFieldsToEncrypt(ValidEntityWithEnableMigrationSupportToday.class))
				.hasSize(1)
				.first()
				.satisfies(field -> assertThat(field.getName()).isEqualTo("email"));
	}
}