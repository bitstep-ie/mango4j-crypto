package ie.bitstep.mango.crypto.core.domain;

import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sort of overkill to be testing enums like this...but may as well.
 */
class CryptoKeyUsageTest {

	@Test
	void encryptionCryptoKeyUsageTypeExists() {
		assertThat(CryptoKeyUsage.valueOf("ENCRYPTION")).isEqualTo(CryptoKeyUsage.ENCRYPTION);
	}

	@Test
	void hmacCryptoKeyUsageTypeExists() {
		assertThat(CryptoKeyUsage.valueOf("HMAC")).isEqualTo(CryptoKeyUsage.HMAC);
	}
}