package ie.bitstep.mango.crypto.core.enums;

import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sort of overkill to be testing enums like this...but may as well.
 */
class NonProdCryptoKeyTypesTest {

	@Test
	void base64CryptoKeyTypeExists() {
		assertThat(NonProdCryptoKeyTypes.valueOf("BASE_64")).isEqualTo(NonProdCryptoKeyTypes.BASE_64);
	}

	@Test
	void base64CryptoKeyTypeGetName() {
		assertThat(NonProdCryptoKeyTypes.BASE_64.getName()).isEqualTo("BASE_64");
	}

	@Test
	void identityCryptoKeyTypeExists() {
		assertThat(NonProdCryptoKeyTypes.valueOf("IDENTITY")).isEqualTo(NonProdCryptoKeyTypes.IDENTITY);
	}

	@Test
	void identityCryptoKeyTypeGetName() {
		assertThat(NonProdCryptoKeyTypes.IDENTITY.getName()).isEqualTo("IDENTITY");
	}

	@Test
	void pbkdf2CryptoKeyTypeExists() {
		assertThat(NonProdCryptoKeyTypes.valueOf("PBKDF2")).isEqualTo(NonProdCryptoKeyTypes.PBKDF2);
	}

	@Test
	void pbkdf2CryptoKeyTypeGetName() {
		assertThat(NonProdCryptoKeyTypes.PBKDF2.getName()).isEqualTo("PBKDF2");
	}
}