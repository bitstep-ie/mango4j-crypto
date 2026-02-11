package ie.bitstep.mango.crypto.core.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sort of overkill to be testing enums like this...but may as well.
 */
class WrappedCryptoKeyTypesTest {

	@Test
	void wrappedCryptoKeyTypeExists() {
		assertThat(WrappedCryptoKeyTypes.valueOf("WRAPPED")).isEqualTo(WrappedCryptoKeyTypes.WRAPPED);
	}

	@Test
	void wrappedCryptoKeyTypeGetName() {
		assertThat(WrappedCryptoKeyTypes.WRAPPED.getName()).isEqualTo("WRAPPED");
	}
}