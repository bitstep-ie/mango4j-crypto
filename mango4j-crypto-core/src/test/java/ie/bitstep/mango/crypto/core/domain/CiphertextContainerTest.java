package ie.bitstep.mango.crypto.core.domain;

import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CiphertextContainerTest {

	private static final String CIPHERTEXT_ATTRIBUTE_NAME = "data";

	@Test
	void constructor() {
		CiphertextContainer ciphertextContainer = new CiphertextContainer(TestData.TEST_BASE_64_CRYPTO_KEY, Map.of(CIPHERTEXT_ATTRIBUTE_NAME, TestData.TEST_FINAL_CIPHERTEXT));

		assertThat(ciphertextContainer.getCryptoKey()).isEqualTo(TestData.TEST_BASE_64_CRYPTO_KEY);
		assertThat(ciphertextContainer.getData()).containsEntry(CIPHERTEXT_ATTRIBUTE_NAME, TestData.TEST_FINAL_CIPHERTEXT);
	}
}