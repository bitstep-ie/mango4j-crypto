package ie.bitstep.mango.crypto.hmac;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HmacUtilsTest {

	@Test
	void testPrivateConstructor() throws NoSuchMethodException {
		Constructor<HmacUtils> constructor = HmacUtils.class.getDeclaredConstructor();
		assertTrue(Modifier.isPrivate(constructor.getModifiers()));
		constructor.setAccessible(true);
		InvocationTargetException exception = assertThrows(InvocationTargetException.class, constructor::newInstance);
		assertEquals("This is a utility class and cannot be instantiated", exception.getCause().getMessage());
	}
}