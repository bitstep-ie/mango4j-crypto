package ie.bitstep.mango.crypto.utils;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

public final class ReflectionUtils {

	/**
	 * Prevents instantiation.
	 */
	private ReflectionUtils() {
		throw new AssertionError();
	}

	/**
	 * Returns a field value as a string, or null if blank.
	 *
	 * @param entity the entity instance
	 * @param sourceField the field to read
	 * @return the field value as string, or null
	 */
	public static String getFieldStringValue(Object entity, Field sourceField) {
		try {
			sourceField.setAccessible(true); // NOSONAR
			Object fieldValue = sourceField.get(entity);
			return (fieldValue == null || fieldValue.toString().isEmpty()) ? null : fieldValue.toString();
		} catch (Exception e) {
			throw new NonTransientCryptoException(String.format("A %s error occurred trying to get the value of field: %s on type: %s", e.getClass().getSimpleName(), sourceField.getName(), entity.getClass().getSimpleName()), e);
		}
	}

	/**
	 * Returns all fields annotated with the supplied annotation.
	 *
	 * @param clazz the class to inspect
	 * @param annotation the annotation type
	 * @return the list of annotated fields
	 */
	public static List<Field> getFieldsByAnnotation(Class<?> clazz, Class<? extends Annotation> annotation) {
		List<Field> fields = new ArrayList<>();
		for (Class<?> currentClass = clazz; currentClass != null; currentClass = currentClass.getSuperclass()) {
			for (Field field : currentClass.getDeclaredFields()) {
				if (field.isAnnotationPresent(annotation)) {
					fields.add(field);
				}
			}
		}
		return fields;
	}
}
