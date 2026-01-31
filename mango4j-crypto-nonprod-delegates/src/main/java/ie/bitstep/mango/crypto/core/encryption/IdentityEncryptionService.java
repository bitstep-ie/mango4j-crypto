package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;

import java.util.Collection;
import java.util.Map;

/**
 * Dummy class to be used for testing/demo/local development purposes only.
 * This class does not perform any encryption whatsoever and will just return the values exactly as is
 * in the clear.
 */
public class IdentityEncryptionService extends EncryptionServiceDelegate {
	public static final String CIPHER_TEXT = "cipherText";

	/**
	 * Just returns the original value of {@code data} without any changes.
	 *
	 * @param encryptionKey crypto key to use for encryption (not used in this dummy implementation)
	 * @param data          data to encrypt
	 * @return {@link CiphertextContainer} representing the data in its original form (unchanged)
	 */
	@Override
	public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
		return new CiphertextContainer(encryptionKey, Map.of(CIPHER_TEXT, data));
	}

	/**
	 * Returns the original plaintext value.
	 *
	 * @param ciphertextContainer the ciphertext container
	 * @return the original value
	 */
	@Override
	public String decrypt(CiphertextContainer ciphertextContainer) {
		return (String) ciphertextContainer.getData().get(CIPHER_TEXT);
	}

	/**
	 * No-op HMAC implementation.
	 *
	 * @param hmacHolders the HMAC holders
	 */
	@Override
	public void hmac(Collection<HmacHolder> hmacHolders) {
		// do nothing
	}

	/**
	 * Returns the supported crypto key type.
	 *
	 * @return the key type name
	 */
	@Override
	public String supportedCryptoKeyType() {
		return NonProdCryptoKeyTypes.IDENTITY.getName();
	}
}
