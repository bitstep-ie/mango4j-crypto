package ie.bitstep.mango.crypto;

import java.lang.reflect.Field;
import java.util.List;

record CipherGroup(
		String cipherGroupName,
		String keySelector,
		List<Field> sourceFields,
		Field targetField,
		Field keyIdField
) {
}