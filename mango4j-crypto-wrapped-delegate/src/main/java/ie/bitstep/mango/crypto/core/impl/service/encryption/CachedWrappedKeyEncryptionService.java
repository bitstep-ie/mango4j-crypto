package ie.bitstep.mango.crypto.core.impl.service.encryption;

import ie.bitstep.mango.collections.ConcurrentCache;
import ie.bitstep.mango.crypto.core.CachedWrappedKeyHolder;
import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import ie.bitstep.mango.crypto.core.enums.WrappedCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.exceptions.KeyAlreadyDestroyedException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.utils.Generators;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_ALG;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_MODE;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_PADDING;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_TEXT;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CONFIGURATION_ERROR;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.DATA_ENCRYPTION_KEY;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.DATA_ENCRYPTION_KEY_ID;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.GCM_TAG_LENGTH;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.IV;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.KEY_SIZE;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

@SuppressWarnings("squid:S1192") // duplicate from non-cached implementation
public class CachedWrappedKeyEncryptionService extends EncryptionServiceDelegate {

	private static final System.Logger LOGGER = System.getLogger(CachedWrappedKeyEncryptionService.class.getName());
	private static final Duration CACHED_KEYS_TTL = Duration.ofMinutes(15);
	private static final Duration CURRENT_KEY_TTL = Duration.ofDays(1);
	private static final Duration KEY_DESTRUCTION_GRACE_PERIOD = Duration.ofSeconds(5);
	private static final Duration KEY_EVICTION_TASK_PERIOD = Duration.ofMinutes(1);

	/**********************************************************************************
	 * NOTE:
	 * Although the cache field is static, it is initialized in the constructor
	 * to allow configuration through Spring. This is safe and acceptable in a Spring
	 * application since the class will typically be instantiated as a managed bean.
	 *********************************************************************************/
	private static final ConcurrentCache<String, CachedWrappedKeyHolder> CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE =
			new ConcurrentCache<>(
					CACHED_KEYS_TTL,
					CURRENT_KEY_TTL,
					KEY_DESTRUCTION_GRACE_PERIOD,
					KEY_EVICTION_TASK_PERIOD,
					Executors.newSingleThreadScheduledExecutor(),
					Clock.systemUTC());


	private final CryptoKeyProvider cryptoKeyProvider;
	private final CiphertextFormatter ciphertextFormatter;

	/**
	 * Creates a cached wrapped key encryption service with custom cache settings.
	 *
	 * @param entryTTL the entry TTL
	 * @param currentEntryTTL the current entry TTL
	 * @param cacheGracePeriod grace period before destruction
	 * @param cryptoKeyProvider the key provider
	 * @param ciphertextFormatter the ciphertext formatter
	 */
	@SuppressWarnings("java:S3010")
	public CachedWrappedKeyEncryptionService(
			Duration entryTTL,
			Duration currentEntryTTL,
			Duration cacheGracePeriod,
			CryptoKeyProvider cryptoKeyProvider,
			CiphertextFormatter ciphertextFormatter) {
		this.cryptoKeyProvider = cryptoKeyProvider;
		this.ciphertextFormatter = ciphertextFormatter;
		CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.setCacheEntryTTL(entryTTL);
		CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.setCurrentEntryTTL(currentEntryTTL);
		CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.setCacheGracePeriod(cacheGracePeriod);
	}

	/**
	 * Creates a cached wrapped key encryption service with default cache settings.
	 *
	 * @param cryptoKeyProvider the key provider
	 * @param ciphertextFormatter the ciphertext formatter
	 */
	public CachedWrappedKeyEncryptionService(CryptoKeyProvider cryptoKeyProvider, CiphertextFormatter ciphertextFormatter) {
		this(
				CACHED_KEYS_TTL,
				CURRENT_KEY_TTL,
				KEY_DESTRUCTION_GRACE_PERIOD,
				cryptoKeyProvider,
				ciphertextFormatter
		);
	}

	/**
	 * Encrypts payload using a cached wrapped data encryption key.
	 *
	 * @param cryptoKey the crypto key
	 * @param payload the plaintext payload
	 * @return the ciphertext container
	 */
	@Override
	public CiphertextContainer encrypt(final CryptoKey cryptoKey, final String payload) {
		try {
			final CryptoKeyConfiguration cep = createConfigPojo(cryptoKey, CryptoKeyConfiguration.class);
			final CipherConfig cipherConfig = CipherConfig.of(cep);
			final var iv = Generators.generateIV(cep.ivSize());
			var wrappedKeyHolder = getCurrentWrappedKeyHolder(cep);
			byte[] key;
			try {
				key = wrappedKeyHolder.key();
			} catch (KeyAlreadyDestroyedException e) {
// race condition - just retry
				LOGGER.log(INFO, "The current key has been destroyed since a reference to it was obtained, this can happen.....trying to get it again");
				wrappedKeyHolder = getCurrentWrappedKeyHolder(cep);
				key = wrappedKeyHolder.key();
				LOGGER.log(INFO, "Got a new reference to it");
			}
			final var dek = generateDataEncryptionKey(key, cipherConfig);
			final var cipher = CipherManager.getCipherInstance(cep.algorithm(), cep.mode(), cep.padding());

			CipherManager.initCipher(ENCRYPT_MODE, cipherConfig, iv, cipher, dek);

			final var encryptedBytes = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

			destroyKey(dek, key);
			return new CiphertextContainer(
					cryptoKey,
					Map.of(
							DATA_ENCRYPTION_KEY_ID, wrappedKeyHolder.keyId(),
							DATA_ENCRYPTION_KEY, ciphertextFormatter.format(wrappedKeyHolder.persistableEncryptedKey()),
							CIPHER_ALG, cep.algorithm().getAlgorithm(),
							CIPHER_MODE, cep.mode().getMode(),
							CIPHER_PADDING, cep.padding().getPadding(),
							KEY_SIZE, cep.keySize(),
							GCM_TAG_LENGTH, cep.gcmTagLength(),
							IV, Base64.getEncoder().encodeToString(iv),
							CIPHER_TEXT, Base64.getEncoder().encodeToString(encryptedBytes)));
		} catch (Exception e) {
			throw new NonTransientCryptoException(CONFIGURATION_ERROR, e);
		}
	}

	/**
	 * Destroys the generated key material.
	 *
	 * @param dek the secret key
	 * @param keyBytes the key bytes to wipe
	 */
	private static void destroyKey(SecretKey dek, byte[] keyBytes) {
		try {
			dek.destroy();
		} catch (DestroyFailedException e) {
			LOGGER.log(DEBUG, "Error occurred calling SecretKey.destroy(). This is common enough and happens because the SecretKey implementation doesn't support it");
		}
// CachedWrappedKeyHolder.key() returns a new key byte array each time
// so we still need to blast away this key byte array once we're done with it
		destroyKeyBytes(keyBytes);
	}

	/**
	 * Overwrites key bytes in memory.
	 *
	 * @param keyBytes the key bytes to wipe
	 */
	private static void destroyKeyBytes(byte[] keyBytes) {
		Arrays.fill(keyBytes, (byte) 0);
	}

	/**
	 * Returns the current cached wrapped key holder.
	 *
	 * @param cep the crypto key configuration
	 * @return the cached key holder
	 */
	private CachedWrappedKeyHolder getCurrentWrappedKeyHolder(CryptoKeyConfiguration cep) {
		synchronized (CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE) {
			CachedWrappedKeyHolder cachedWrappedKeyHolder = CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.getCurrent();
			if (cachedWrappedKeyHolder != null) {
				return cachedWrappedKeyHolder;
			} else {
				return newCachedWrappedKeyHolder(cep);
			}
		}
	}

	/**
	 * Creates and caches a new wrapped key holder.
	 *
	 * @param cep the crypto key configuration
	 * @return the new cached holder
	 */
	private CachedWrappedKeyHolder newCachedWrappedKeyHolder(CryptoKeyConfiguration cep) {
// Current key not set or expired, create a new one and set as current
		final var keyId = UUID.randomUUID().toString();
		final var dek = Generators.generateRandomBits(cep.keySize());
		final var keyEncryptionKey = getWrappingKey(cep.keyEncryptionKey());

		CachedWrappedKeyHolder cachedWrappedKeyHolder = CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.putCurrent(keyId, new CachedWrappedKeyHolder(
						keyId,
						dek,
						super.encryptionService.encrypt(keyEncryptionKey, Base64.getEncoder().encodeToString(dek))
				)
		);
		destroyKeyBytes(dek);
		return cachedWrappedKeyHolder;
	}

	/**
	 * Returns the wrapping key for a key ID.
	 *
	 * @param cryptoKeyId the wrapping key ID
	 * @return the crypto key
	 */
	private CryptoKey getWrappingKey(String cryptoKeyId) {
		return cryptoKeyProvider.getById(cryptoKeyId);
	}

	/**
	 * Decrypts ciphertext using a cached wrapped data encryption key.
	 *
	 * @param ciphertextContainer the ciphertext container
	 * @return the decrypted plaintext
	 */
	@Override
	public String decrypt(final CiphertextContainer ciphertextContainer) {
		try {
			final EncryptedDataConfig edc = createConfigPojo(ciphertextContainer.getData(), EncryptedDataConfig.class);
			final CipherConfig cipherConfig = CipherConfig.of(edc);
			final var iv = Base64.getDecoder().decode(edc.iv());

			CachedWrappedKeyHolder cachedWrappedKeyHolder = getWrappedKeyHolder(
					ciphertextContainer,
					edc);

			byte[] key;
			try {
				key = cachedWrappedKeyHolder.key();
			} catch (KeyAlreadyDestroyedException e) {
// race condition - just retry
				LOGGER.log(INFO, "The cached key has been destroyed since a reference to it was obtained, this can happen.....trying to get it again");
				cachedWrappedKeyHolder = getWrappedKeyHolder(
						ciphertextContainer,
						edc);
				key = cachedWrappedKeyHolder.key();
				LOGGER.log(INFO, "Got a new reference to it");
			}

			final var dek = new SecretKeySpec(key, edc.algorithm().getAlgorithm());

			final var cipher = CipherManager.getCipherInstance(CipherConfig.of(edc));

			CipherManager.initCipher(DECRYPT_MODE, cipherConfig, iv, cipher, dek);

			final var decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(edc.cipherText()));
			destroyKey(dek, key);
			return new String(decryptedBytes, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new NonTransientCryptoException(CONFIGURATION_ERROR, e);
		}
	}

	/**
	 * Returns a wrapped key holder for a ciphertext container.
	 *
	 * @param ciphertextContainer the ciphertext container
	 * @param edc the encrypted data config
	 * @return the cached key holder
	 */
	private CachedWrappedKeyHolder getWrappedKeyHolder(CiphertextContainer ciphertextContainer, EncryptedDataConfig edc) {
		synchronized (CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE) {
			final String keyid = ciphertextContainer.getData().get(DATA_ENCRYPTION_KEY_ID).toString();
			CachedWrappedKeyHolder cachedWrappedKeyHolder = CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.get(keyid);

			if (cachedWrappedKeyHolder != null) {
				return cachedWrappedKeyHolder;
			} else {
// key not cached, create holder and put it in cache
				final var encodedKey = super.encryptionService.decrypt(edc.dataEncryptionKey());
				final var decodedKey = Base64.getDecoder().decode(encodedKey.getBytes(StandardCharsets.UTF_8));

				cachedWrappedKeyHolder = new CachedWrappedKeyHolder(
						keyid,
						decodedKey,
						ciphertextContainer
				);

				return CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE.put(cachedWrappedKeyHolder.keyId(), cachedWrappedKeyHolder);
			}
		}
	}

	/**
	 * HMAC is not supported by this implementation.
	 *
	 * @param list the HMAC holders
	 */
	@Override
	public void hmac(final Collection<HmacHolder> list) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns the supported crypto key type.
	 *
	 * @return the key type name
	 */
	@Override
	public String supportedCryptoKeyType() {
		return WrappedCryptoKeyTypes.CACHED_WRAPPED.getName();
	}

	/**
	 * Generates a data encryption key from cached key bytes.
	 *
	 * @param key the key bytes
	 * @param cipherConfig the cipher config
	 * @return the secret key
	 */
	private static SecretKey generateDataEncryptionKey(final byte[] key, final CipherConfig cipherConfig) {
		return new SecretKeySpec(key, cipherConfig.algorithm().getAlgorithm());
	}
}
