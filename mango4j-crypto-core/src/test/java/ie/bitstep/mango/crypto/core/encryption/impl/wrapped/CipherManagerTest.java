package ie.bitstep.mango.crypto.core.encryption.impl.wrapped;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import static org.assertj.core.api.Assertions.assertThat;

class CipherManagerTest {

	@Test
	void constructor() throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
		Constructor<CipherManager> constructor = CipherManager.class.getDeclaredConstructor();
		constructor.setAccessible(true);
		assertThat(constructor.newInstance()).isInstanceOf(CipherManager.class);
	}
}