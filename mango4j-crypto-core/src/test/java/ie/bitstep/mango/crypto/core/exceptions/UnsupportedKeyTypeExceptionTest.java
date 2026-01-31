package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UnsupportedKeyTypeExceptionTest {

	@Test
	void unsupportedKeyTypeExceptionNewInstance() {
		UnsupportedKeyTypeException unsupportedKeyTypeException = new UnsupportedKeyTypeException(TestData.testCryptoKey());

		assertThat(unsupportedKeyTypeException.getMessage()).isEqualTo(String.format("No Encryption Service was registered for crypto key [id:%s, type:%s, usage:%s]",
				TestData.TEST_CRYPTO_KEY_ID, TestData.TEST_CRYPTO_KEY_TYPE, TestData.TEST_CRYPTO_KEY_USAGE));
	}
}