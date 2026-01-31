package ie.bitstep.mango.crypto.utils;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.utils.ReflectionUtils;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReflectionUtilsTest {

	@Test
	void constructor() throws Exception {
		Constructor<ReflectionUtils> constructor = ReflectionUtils.class.getDeclaredConstructor();
		constructor.setAccessible(true);

		assertThatThrownBy(constructor::newInstance).hasCauseInstanceOf(AssertionError.class);
	}

	@Test
	void getFieldStringValue() throws NoSuchFieldException {
		assertThat(ReflectionUtils.getFieldStringValue(new TestClass(), TestClass.class.getDeclaredField("field1"))).isEqualTo("testValue1");
	}

	@Test
	void getFieldStringValueNull() throws NoSuchFieldException {
		assertThat(ReflectionUtils.getFieldStringValue(new TestClass(), TestClass.class.getDeclaredField("field4"))).isNull();
	}

	@Test
	void getFieldStringValueEmpty() throws NoSuchFieldException {
		TestClass entity = new TestClass();
		entity.field4 = "";
		assertThat(ReflectionUtils.getFieldStringValue(entity, TestClass.class.getDeclaredField("field4"))).isNull();
	}

	@Test
	void getFieldStringValueExceptionFailure() throws NoSuchFieldException {
		ExceptionThrowingTestClass exceptionThrowingTestClass = new ExceptionThrowingTestClass();
		Field field1 = TestClass.class.getDeclaredField("field1");

		assertThatThrownBy(() -> ReflectionUtils.getFieldStringValue(exceptionThrowingTestClass, field1))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasMessage("A IllegalArgumentException error occurred trying to get the value of field: field1 on type: " + ExceptionThrowingTestClass.class.getSimpleName());
	}

	private static class TestClass {
		@Hmac
		private final String field1 = "testValue1";

		@Hmac
		private final String field2 = "testValue2";

		@Encrypt
		private final String field3 = "testValue3";

		private String field4; // NOSONAR: uses to test PropertyAccessor failure
	}

	private static class ExceptionThrowingTestClass {
		private final String field = "testValue"; // NOSONAR: uses for test cases
	}

	@Test
	void getFieldsByAnnotation() throws NoSuchFieldException {
		List<Field> fieldsByAnnotation = ReflectionUtils.getFieldsByAnnotation(TestClass.class, Hmac.class);

		assertThat(fieldsByAnnotation)
				.contains(TestClass.class.getDeclaredField("field1"))
				.contains(TestClass.class.getDeclaredField("field2"))
				.doesNotContain(TestClass.class.getDeclaredField("field3"));
	}
}