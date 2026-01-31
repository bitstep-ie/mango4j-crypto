package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.UniqueGroup;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;

import static java.lang.String.format;

public final class FieldValidator {

	/**
	 * Utility class for validating HMAC field definitions.
	 */
	private FieldValidator() { // NOSONAR
		// SONAR, add private constructor
	}

	/**
	 * Validates that a source field is a valid HMAC source field.
	 *
	 * @param hmacSourceField       the field to validate
	 * @param annotatedEntityClass  the entity class that owns the field
	 */
	static void validateSourceHmacField(Field hmacSourceField, Class<?> annotatedEntityClass) {
		if (!Modifier.isTransient(hmacSourceField.getModifiers())) {
			throw new NonTransientCryptoException(format("%s has a field named %s marked with @%s but it is not transient. " +
							"Please mark any fields annotated with @%s as transient",
					annotatedEntityClass.getSimpleName(), hmacSourceField.getName(), Hmac.class.getSimpleName(), Hmac.class.getSimpleName()));
		} else if (!String.class.isAssignableFrom(hmacSourceField.getType())) {
			throw new NonTransientCryptoException(format("%s has a field named %s marked with @%s but it is of type of %s. " +
							"HMAC fields can only be of type %s",
					annotatedEntityClass.getSimpleName(), hmacSourceField.getName(), Hmac.class.getSimpleName(), hmacSourceField.getType(), String.class.getSimpleName()));
		} else if (hmacSourceField.isAnnotationPresent(UniqueGroup.class)
				&& Arrays.stream(hmacSourceField.getDeclaredAnnotation(Hmac.class).purposes()).noneMatch(purposes -> purposes == Hmac.Purposes.UNIQUE)) {
			throw new NonTransientCryptoException(format("%s has a HMAC field named %s marked with @%s with but it does not have a purpose of %s",
					annotatedEntityClass.getSimpleName(), hmacSourceField.getName(), UniqueGroup.class.getSimpleName(), Hmac.Purposes.UNIQUE));
		}
	}
}
