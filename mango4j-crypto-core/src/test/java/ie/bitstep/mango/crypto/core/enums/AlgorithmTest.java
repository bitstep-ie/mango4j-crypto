package ie.bitstep.mango.crypto.core.enums;

import ie.bitstep.mango.crypto.core.enums.Algorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AlgorithmTest {

	@Test
	void fromValue() {
		assertThat(Algorithm.fromValue("AES")).isEqualTo(Algorithm.AES);
	}

	@Test
	void fromValueException() {
		assertThrows(IllegalArgumentException.class, () -> Algorithm.fromValue("BAD"));
	}
}