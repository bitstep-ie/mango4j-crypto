package ie.bitstep.mango.crypto.core.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sort of overkill to be testing enums like this...but may as well.
 */
class CoreCryptoKeyTypesTest {

	@Test
	void base64CryptoKeyTypeExists() {
		assertThat(CoreCryptoKeyTypes.valueOf("BASE_64")).isEqualTo(CoreCryptoKeyTypes.BASE_64);
	}

	@Test
	void base64CryptoKeyTypeGetName() {
		assertThat(CoreCryptoKeyTypes.BASE_64.getName()).isEqualTo("BASE_64");
	}

	@Test
	void identityCryptoKeyTypeExists() {
		assertThat(CoreCryptoKeyTypes.valueOf("IDENTITY")).isEqualTo(CoreCryptoKeyTypes.IDENTITY);
	}

	@Test
	void identityCryptoKeyTypeGetName() {
		assertThat(CoreCryptoKeyTypes.IDENTITY.getName()).isEqualTo("IDENTITY");
	}

	@Test
	void pbkdf2CryptoKeyTypeExists() {
		assertThat(CoreCryptoKeyTypes.valueOf("PBKDF2")).isEqualTo(CoreCryptoKeyTypes.PBKDF2);
	}

	@Test
	void pbkdf2CryptoKeyTypeGetName() {
		assertThat(CoreCryptoKeyTypes.PBKDF2.getName()).isEqualTo("PBKDF2");
	}
}