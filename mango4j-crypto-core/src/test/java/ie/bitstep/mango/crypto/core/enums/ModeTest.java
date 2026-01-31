package ie.bitstep.mango.crypto.core.enums;

import ie.bitstep.mango.crypto.core.enums.Mode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ModeTest {

	@Test
	void fromValue() {
		assertThat(Mode.fromValue("GCM")).isEqualTo(Mode.GCM);
	}

	@Test
	void fromValueException() {
		assertThrows(IllegalArgumentException.class, () -> Mode.fromValue("BAD"));
	}
}