package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategy;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list.TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FieldValidatorTest {

	@Test
	void privateConstructor() throws Exception {
		Constructor<FieldValidator> constructor = FieldValidator.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertThat(constructor.newInstance()).isInstanceOf(FieldValidator.class);
	}

	@Test
	void constructorNonTransientHmacFields() throws NoSuchFieldException {
		Field panField = InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField.class.getDeclaredField("pan");
		assertThatThrownBy(() -> FieldValidator.validateSourceHmacField(panField, InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField.class))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyNonTransientField has a field named pan marked with @Hmac but it is not transient. Please mark any fields annotated with @Hmac as transient");
	}

	@Test
	void constructorUniqueGroupFieldWithUniquePurpose() throws NoSuchFieldException {
		Field panField = TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroup.class.getDeclaredField("pan");
		assertThatNoException().isThrownBy(() -> FieldValidator.validateSourceHmacField(panField, TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose.class));
	}

	@Test
	void constructorUniqueGroupFieldButNoUniquePurpose() throws NoSuchFieldException {
		Field panField = TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose.class.getDeclaredField("pan");
		assertThatThrownBy(() -> FieldValidator.validateSourceHmacField(panField, TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose.class))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("TestAnnotatedEntityForListHmacFieldStrategyWithHmacOnlyUniqueGroupWithNoUniquePurpose has a HMAC field named pan marked with @UniqueGroup with but it does not have a purpose of UNIQUE");
	}

	@Test
	void constructorNoUniqueGroupFieldButUniquePurpose() {
		assertThatNoException().isThrownBy(() -> FieldValidator.validateSourceHmacField(TestAnnotatedEntityForListHmacFieldStrategy.class.getDeclaredField("userName"), TestAnnotatedEntityForListHmacFieldStrategy.class));
	}

	@Test
	void constructorNonStringHmacFields() throws NoSuchFieldException {
		Field panField = InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField.class.getDeclaredField("pan");
		assertThatThrownBy(() -> FieldValidator.validateSourceHmacField(panField, InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField.class))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("InvalidAnnotatedEntityForListHmacFieldStrategyNonStringField has a field named pan marked with @Hmac but it is of type of int. HMAC fields can only be of type String");
	}
}
