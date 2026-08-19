package ie.bitstep.mango.crypto;

import java.lang.reflect.Field;
import java.util.List;

record CipherGroup(
		String KeySelector,
		Type type,
		List<Field> sourceFields,
		Field targetField
) {
	enum Type { // Changed to public as it's part of the public record's component type
		SINGLE,
		COMPOUND
	}
}