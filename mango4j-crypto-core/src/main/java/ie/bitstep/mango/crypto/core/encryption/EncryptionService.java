package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.factories.ObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public final class EncryptionService {
	private final Map<String, EncryptionServiceDelegate> encryptionServiceDelegates = new HashMap<>();
	private final CiphertextFormatter ciphertextFormatter;
	private final ObjectMapperFactory objectMapperFactory;

	/**
	 * Creates a service with delegates and a key provider.
	 *
	 * @param encryptionServiceDelegates delegate implementations
	 * @param cryptoKeyProvider key provider for lookup
	 */
	public EncryptionService(Collection<EncryptionServiceDelegate> encryptionServiceDelegates,
							 CryptoKeyProvider cryptoKeyProvider) {
		this(encryptionServiceDelegates, cryptoKeyProvider, new ConfigurableObjectMapperFactory());
	}

	/**
	 * Creates a service with delegates, key provider, and mapper factory.
	 *
	 * @param encryptionServiceDelegates delegate implementations
	 * @param cryptoKeyProvider key provider for lookup
	 * @param objectMapperFactory mapper factory
	 */
	public EncryptionService(Collection<EncryptionServiceDelegate> encryptionServiceDelegates,
							 CryptoKeyProvider cryptoKeyProvider,
							 ObjectMapperFactory objectMapperFactory) {
		this(encryptionServiceDelegates, new CiphertextFormatter(cryptoKeyProvider, objectMapperFactory), objectMapperFactory);
	}

	/**
	 * Creates a service with delegates, ciphertext formatter, and mapper factory.
	 *
	 * @param encryptionServiceDelegates delegate implementations
	 * @param ciphertextFormatter ciphertext formatter
	 * @param objectMapperFactory mapper factory
	 */
	public EncryptionService(Collection<EncryptionServiceDelegate> encryptionServiceDelegates,
							 CiphertextFormatter ciphertextFormatter,
							 ObjectMapperFactory objectMapperFactory) {
		this.ciphertextFormatter = ciphertextFormatter;
		this.objectMapperFactory = objectMapperFactory;
		encryptionServiceDelegates.forEach(encryptionServiceDelegate -> {
			this.encryptionServiceDelegates.put(encryptionServiceDelegate.supportedCryptoKeyType(), encryptionServiceDelegate);
			encryptionServiceDelegate.setEncryptionServiceReference(this);
		});
	}

	/**
	 * Returns the delegate that supports the supplied key.
	 *
	 * @param cryptoKey the crypto key
	 * @return the matching delegate
	 */
	private EncryptionServiceDelegate getInstance(CryptoKey cryptoKey) {
		EncryptionServiceDelegate result;
		if (cryptoKey.getType() == null || (result = encryptionServiceDelegates.get(cryptoKey.getType())) == null) {
			throw new UnsupportedKeyTypeException(cryptoKey);
		}
		return result;
	}

	/**
	 * Encrypts data with the key.
	 *
	 * @param encryptionKey {@link CryptoKey} to use for encryption.
	 * @param data          data to be encrypted.
	 * @return {@link CiphertextContainer} representing the encrypted data.
	 */
	public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
		return getInstance(encryptionKey).encrypt(encryptionKey, data);
	}

	/**
	 * Encrypts a batch of data with the key.
	 *
	 * @param encryptionKey {@link CryptoKey} to use for encryption.
	 * @param data          list of data to be encrypted.
	 * @return List of {@link CiphertextContainer CiphertextContainers} representing the encrypted data list.
	 */
	public List<CiphertextContainer> encrypt(CryptoKey encryptionKey, List<String> data) {
		return getInstance(encryptionKey).encrypt(encryptionKey, data);
	}

	/**
	 * Decrypts data.
	 *
	 * @param ciphertextContainer {@link CiphertextContainer} representing the data to decrypt.
	 * @return original decrypted data.
	 */
	private String decrypt(CiphertextContainer ciphertextContainer) {
		return getInstance(ciphertextContainer.getCryptoKey()).decrypt(ciphertextContainer);
	}

	/**
	 * Convenience method to decrypt a piece of cipherText.
	 *
	 * @param cipherText The previously stored ciphertext.
	 * @return The decrypted cipherText.
	 */
	public String decrypt(String cipherText) {
		return decrypt(ciphertextFormatter.parse(cipherText));
	}


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
	public void hmac(Collection<HmacHolder> hmacHolders) {
		hmacHolders.stream()
			.collect(Collectors.groupingBy(hmacHolder -> getInstance(hmacHolder.getCryptoKey())))
			.forEach(EncryptionServiceDelegate::hmac);
	}

	/**
	 * Returns the ObjectMapperFactory used by this service.
	 *
	 * @return the mapper factory
	 */
	public ObjectMapperFactory getObjectMapperFactory() {
		return objectMapperFactory;
	}
}
