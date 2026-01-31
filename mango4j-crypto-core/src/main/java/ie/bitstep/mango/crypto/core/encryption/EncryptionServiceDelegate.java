package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public abstract class EncryptionServiceDelegate {
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
	public abstract CiphertextContainer encrypt(CryptoKey encryptionKey, String data);

	/**
	 * Can be overridden to provide native batch encrypt functionality.
	 * @param encryptionKey {@link CryptoKey} to use for encryption.
	 * @param data 			List of data items to be encrypted.
	 * @return List of {@link CiphertextContainer CiphertextContainers} representing the encrypted data.
	 */
	public List<CiphertextContainer> encrypt(CryptoKey encryptionKey, List<String> data) {
		return data.stream().map(datum -> encrypt(encryptionKey, datum)).toList();
	}

	/**
	 * Decrypts data.
	 *
	 * @param ciphertextContainer {@link CiphertextContainer} representing the data to decrypt.
	 * @return original decrypted data.
	 */
	public abstract String decrypt(CiphertextContainer ciphertextContainer);

	/**
	 * Calculates HMACs for the values in the list of {@link HmacHolder HMAC values}.
	 *
	 * @param hmacHolders {@link HmacHolder HMAC values} to calculate HMACs for.
	 *                    <br>
	 *                    See {@link HmacHolder} documentation for the concept of a Hmac Holder and why we use them.
	 *
	 *                    <br>
	 *                    <br>
	 *                    <b>Note for Implementation developers:</b> Remember that during key rotations that each {@link HmacHolder} element can have a separate
	 *                    {@link CryptoKey CryptoKey} object and needs to have its HMAC calculated with
	 *                    that specific {@link CryptoKey}, so several calls may need to be made to the cryptographic provider.
	 *                    Do not assume that all list elements use the same HMAC key!!!
	 *                    Implementations that support batching functionality need to split up this list and group it by {@link CryptoKey}
	 *                    then perform the HMAC operation for each group.
	 */
	public abstract void hmac(Collection<HmacHolder> hmacHolders);

	/**
	 * Injects the parent service reference.
	 *
	 * @param encryptionService the service instance
	 */
	void setEncryptionServiceReference(EncryptionService encryptionService) {
		this.encryptionService = encryptionService;
	}

	/**
	 * Converts a key configuration into a typed POJO.
	 *
	 * @param cryptoKey the crypto key
	 * @param c the target class
	 * @param <T> the target type
	 * @return the configuration POJO
	 */
	public <T> T createConfigPojo(final CryptoKey cryptoKey, Class<T> c) {
		return createConfigPojo(cryptoKey.getConfiguration(), c);
	}

	/**
	 * Converts a configuration map into a typed POJO.
	 *
	 * @param configMap the configuration map
	 * @param c the target class
	 * @param <T> the target type
	 * @return the configuration POJO
	 */
	public <T> T createConfigPojo(final Map<String, Object> configMap, Class<T> c) {
		return encryptionService.getObjectMapperFactory().objectMapper().convertValue(configMap, c);
	}
}
