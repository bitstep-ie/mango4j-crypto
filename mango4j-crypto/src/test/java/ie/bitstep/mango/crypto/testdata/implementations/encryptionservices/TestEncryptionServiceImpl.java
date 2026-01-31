package ie.bitstep.mango.crypto.testdata.implementations.encryptionservices;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import ie.bitstep.mango.crypto.testdata.TestData;

import java.util.Collection;

public class TestEncryptionServiceImpl extends EncryptionServiceDelegate {

	@Override
	public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
		return null;
	}

	@Override
	public String decrypt(CiphertextContainer ciphertextContainer) {
		return null;
	}

	@Override
	public void hmac(Collection<HmacHolder> hmacHolders) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String supportedCryptoKeyType() {
		return TestData.TEST_NEW_CRYPTO_KEY_TYPE;
	}
}