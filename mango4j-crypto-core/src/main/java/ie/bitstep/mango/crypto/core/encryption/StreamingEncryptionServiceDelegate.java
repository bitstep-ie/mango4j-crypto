package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;

public abstract class StreamingEncryptionServiceDelegate {
	protected EncryptionService encryptionService = null;

	/**
	 * @return A string constant of the supported crypto key type.
	 */
	public abstract String supportedCryptoKeyType();

	/**
	 * Encrypts data with the key.
	 *
	 * @param encryptionKey {@link CryptoKey} to use for encryption.
	 * @param data          data to be encrypted.
	 * @return {@link CiphertextContainer} representing the encrypted data.
	 */
	public abstract byte[] encrypt(CryptoKey encryptionKey, byte[] data);

	/**
	 * Decrypts data.
	 *
	 * @param cipher {@link byte[]} representing the data to decrypt.
	 * @return original decrypted data.
	 */
	public abstract byte[] decrypt(byte[] cipher);
}
