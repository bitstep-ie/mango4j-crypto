package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoKeyNotFoundExceptionTest {

	@Test
	void cryptoKeyNotFoundExceptionNewInstance() {
		CryptoKeyNotFoundException cryptoKeyNotFoundException = new CryptoKeyNotFoundException(TestData.TEST_CRYPTO_KEY_ID);

		assertThat(cryptoKeyNotFoundException.getMessage()).isEqualTo("Crypto Key with ID '" + TestData.TEST_CRYPTO_KEY_ID + "' not found");
	}
}