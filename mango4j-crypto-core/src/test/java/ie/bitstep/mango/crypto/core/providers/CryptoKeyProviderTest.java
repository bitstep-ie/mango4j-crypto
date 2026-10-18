package ie.bitstep.mango.crypto.core.providers;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static ie.bitstep.mango.crypto.core.testdata.TestData.testCryptoKey;
import static org.junit.jupiter.api.Assertions.assertSame;

public class CryptoKeyProviderTest {

	@Test
	void defaultMethodDelegatesToNoArg() {
		CryptoKey testCryptoKey = testCryptoKey();

		CryptoKeyProvider cryptoKeyProviderImplWithoutGetCurrentEncryptionKeyWithKeySelectorMethod = new CryptoKeyProvider() {
			@Override
			public CryptoKey getById(String cryptoKeyId) {
				return null;
			}

			@Override
			public CryptoKey getCurrentEncryptionKey() {
				return testCryptoKey;
			}

			@Override
			public List<CryptoKey> getCurrentHmacKeys() {
				return List.of();
			}

			@Override
			public List<CryptoKey> getAllCryptoKeys() {
				return List.of();
			}
		};

		assertSame(testCryptoKey, cryptoKeyProviderImplWithoutGetCurrentEncryptionKeyWithKeySelectorMethod.getCurrentEncryptionKey("any-selector"));
	}
}
