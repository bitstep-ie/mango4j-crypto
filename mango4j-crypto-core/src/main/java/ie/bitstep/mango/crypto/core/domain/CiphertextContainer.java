package ie.bitstep.mango.crypto.core.domain;

import ie.bitstep.mango.crypto.core.encryption.EncryptionService;

import java.util.Map;

/**
 * Class used to represent the result of an encryption operation.
 * {@link EncryptionService EncryptionService} implementations
 * must return this from the
 * {@link EncryptionService#encrypt(CryptoKey, String) encrypt(CryptoKey, String)}
 * method with all fields populated correctly in order for this library to work properly.
 */
public class CiphertextContainer {

	private final CryptoKey cryptoKey;
	private final Map<String, Object> data;

	/**
	 * Creates a container for ciphertext data.
	 *
	 * @param cryptoKeyId the key used for encryption
	 * @param container the ciphertext payload data
	 */
	public CiphertextContainer(CryptoKey cryptoKeyId, Map<String, Object> container) {
		this.cryptoKey = cryptoKeyId;
		this.data = container;
	}

	/**
	 * Returns the crypto key associated with this ciphertext.
	 *
	 * @return the crypto key
	 */
	public CryptoKey getCryptoKey() {
		return cryptoKey;
	}

	/**
	 * Returns the ciphertext payload data.
	 *
	 * @return the ciphertext data map
	 */
	public Map<String, Object> getData() {
		return data;
	}
}
