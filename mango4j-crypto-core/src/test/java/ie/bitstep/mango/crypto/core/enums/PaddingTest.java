package ie.bitstep.mango.crypto.core.enums;

import ie.bitstep.mango.crypto.core.enums.Padding;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PaddingTest {

	@Test
	void fromValue() {
		assertThat(Padding.fromValue("NoPadding")).isEqualTo(Padding.NO_PADDING);
	}

	@Test
	void fromValueException() {
		assertThrows(IllegalArgumentException.class, () -> Padding.fromValue("BAD"));
	}

}