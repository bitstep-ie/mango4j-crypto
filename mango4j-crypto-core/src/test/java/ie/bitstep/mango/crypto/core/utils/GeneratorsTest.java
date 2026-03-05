package ie.bitstep.mango.crypto.core.utils;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class GeneratorsTest {

	@Test
	void constructor() throws NoSuchMethodException {
		Constructor<Generators> constructor = Generators.class.getDeclaredConstructor();
		constructor.setAccessible(true);

		assertThatNoException().isThrownBy(constructor::newInstance);
	}

	@Test
	void generateRandomBytes() {
		byte[] zeroBytes = new byte[5];
		byte[] bytes = Generators.generateRandomBytes(zeroBytes.length);

		assertThat(bytes).isNotEqualTo(zeroBytes);
	}

	@Test
	void generateRandomBits() {
		byte[] zeroBytes = new byte[32];
		byte[] bytes = Generators.generateRandomBits(zeroBytes.length * 8);

		assertThat(bytes)
			.hasSameSizeAs(zeroBytes)
			.isNotEqualTo(zeroBytes);
	}

	@Test
	void generateIV() {
		byte[] iv = Generators.generateIV(16);

		assertThat(iv).hasSize(16);
	}
}