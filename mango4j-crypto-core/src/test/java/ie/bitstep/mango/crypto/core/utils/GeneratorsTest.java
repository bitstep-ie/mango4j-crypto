package ie.bitstep.mango.crypto.core.utils;

import ie.bitstep.mango.crypto.core.utils.Generators;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GeneratorsTest {

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