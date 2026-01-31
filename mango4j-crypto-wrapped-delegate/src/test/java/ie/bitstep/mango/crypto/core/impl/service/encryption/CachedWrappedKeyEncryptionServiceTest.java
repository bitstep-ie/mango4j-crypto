package ie.bitstep.mango.crypto.core.impl.service.encryption;

import ie.bitstep.mango.collections.ConcurrentCache;
import ie.bitstep.mango.crypto.core.CachedWrappedKeyHolder;
import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.Base64EncryptionService;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.encryption.EncryptionServiceDelegate;
import ie.bitstep.mango.crypto.core.enums.Algorithm;
import ie.bitstep.mango.crypto.core.enums.Mode;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.enums.WrappedCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.exceptions.KeyAlreadyDestroyedException;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.utils.Generators;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicReference;

import static ie.bitstep.mango.crypto.core.enums.Mode.CBC;
import static ie.bitstep.mango.crypto.core.enums.Mode.GCM;
import static ie.bitstep.mango.crypto.core.enums.Padding.NO_PADDING;
import static ie.bitstep.mango.crypto.core.enums.Padding.PKCS5_PADDING;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_ALG;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_MODE;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_PADDING;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.DATA_ENCRYPTION_KEY;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.GCM_TAG_LENGTH;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.IV_SIZE;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.KEY_ENCRYPTION_KEY;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.KEY_SIZE;
import static ie.bitstep.mango.crypto.core.testdata.TestKeyUtils.isEmpty;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mockStatic;

class CachedWrappedKeyEncryptionServiceTest implements CryptoKeyProvider {
	private static final byte[] TEST_KEY_BYTES = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	private static final byte[] TEST_24_IV_BYTES = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
	private static final byte[] TEST_16_IV_BYTES = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	public static final String WRAPPING_KEY_ID = "WRAPPING-KEY-ID";
	public static final String CIPHERTEXT_ALGORITHM_FIELD_NAME = "algorithm";
	public static final String CIPHER_TEXT_FIELD_NAME = "cipherText";
	public static final String CIPHERTEXT_DATA_ENCRYPTION_KEY_FIELD_NAME = "dek";
	public static final String CIPHERTEXT_DATA_ENCRYPTION_KEY_ID_FIELD_NAME = "dekId";
	public static final String ALGORITHM_VALUE = "AES";
	public static final String CIPHERTEXT_GCM_TAG_LENGTH_FIELD_NAME = "gcmTagLength";
	public static final String CIPHERTEXT_IV_FIELD_NAME = "iv";
	public static final String CIPHERTEXT_KEY_SIZE_FIELD_NAME = "keySize";
	public static final String CIPHERTEXT_MODE_FIELD_NAME = "mode";
	public static final String CIPHERTEXT_PADDING_FIELD_NAME = "padding";
	public static final String NO_PADDING_VALUE = "NoPadding";
	public static final String PKCS5_PADDING_VALUE = "PKCS5Padding";
	public static final String GCM_MODE_VALUE = "GCM";
	public static final String CBC_MODE_VALUE = "CBC";
	public static final String AES_GCM_CACHED_WRAPPED_KEY_ID = "AES-GCM";
	public static final int GCM_TAG_LENGTH_VALUE = 128;
	public static final int GCM_CIPHERTEXT_LENGTH_VALUE = 36;
	public static final int CBC_CIPHERTEXT_LENGTH_VALUE = 24;


	static {
		new Random().nextBytes(TEST_KEY_BYTES);
	}

	private final String data = "hello dolly";
	private final Map<String, CryptoKey> cryptoKeys = new HashMap<>();
	private CryptoKey aesGCMKey;
	private byte[] currentKeyBytes;
	private CachedWrappedKeyHolder mockedCachedWrappedKeyHolder;
	private EncryptionService encryptionService;
	private CryptoKey cbcCryptoKey;
	private CryptoKey noCipherModeKey;

	@BeforeEach
	@AfterEach
	void setup() {
		clearCache();
		encryptionService = setUp(TEST_KEY_BYTES.length);
	}

	@Override
	public CryptoKey getById(String s) {
		return cryptoKeys.get(s);
	}

	@Override
	public CryptoKey getCurrentEncryptionKey() {
		return getById("AES-CBC");
	}

	@Override
	public List<CryptoKey> getCurrentHmacKeys() {
		return List.of();
	}

	@Override
	public List<CryptoKey> getAllCryptoKeys() {
		return cryptoKeys.values().stream().toList();
	}

	EncryptionService setUp(int keySize) {
		cryptoKeys.clear();
		CryptoKey wrappingCryptoKey = new CryptoKey();
		wrappingCryptoKey.setId(WRAPPING_KEY_ID);
		wrappingCryptoKey.setType(NonProdCryptoKeyTypes.BASE_64.getName());
		wrappingCryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		wrappingCryptoKey.setKeyStartTime(Instant.now());
		cryptoKeys.put(wrappingCryptoKey.getId(), wrappingCryptoKey);

		cbcCryptoKey = new CryptoKey();
		cbcCryptoKey.setId("AES-CBC");
		cbcCryptoKey.setType(WrappedCryptoKeyTypes.CACHED_WRAPPED.getName());
		cbcCryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cbcCryptoKey.setKeyStartTime(Instant.now());
		cbcCryptoKey.setConfiguration(
				Map.of(
						KEY_ENCRYPTION_KEY, WRAPPING_KEY_ID,
						KEY_SIZE, TEST_KEY_BYTES.length,
						IV_SIZE, TEST_16_IV_BYTES.length,
						CIPHER_ALG, Algorithm.AES,
						CIPHER_MODE, CBC,
						CIPHER_PADDING, PKCS5_PADDING,
						GCM_TAG_LENGTH, GCM_TAG_LENGTH_VALUE
				)
		);
		cryptoKeys.put(cbcCryptoKey.getId(), cbcCryptoKey);

		aesGCMKey = new CryptoKey();
		aesGCMKey.setId(AES_GCM_CACHED_WRAPPED_KEY_ID);
		aesGCMKey.setType(WrappedCryptoKeyTypes.CACHED_WRAPPED.getName());
		aesGCMKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		aesGCMKey.setKeyStartTime(Instant.now());
		aesGCMKey.setConfiguration(
				Map.of(
						KEY_ENCRYPTION_KEY, WRAPPING_KEY_ID,
						KEY_SIZE, keySize,
						IV_SIZE, TEST_24_IV_BYTES.length,
						CIPHER_ALG, Algorithm.AES,
						CIPHER_MODE, GCM,
						CIPHER_PADDING, NO_PADDING,
						GCM_TAG_LENGTH, GCM_TAG_LENGTH_VALUE
				)
		);
		cryptoKeys.put(aesGCMKey.getId(), aesGCMKey);

		noCipherModeKey = new CryptoKey();
		noCipherModeKey.setId("AES-NONE");
		noCipherModeKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		noCipherModeKey.setType(WrappedCryptoKeyTypes.CACHED_WRAPPED.getName());
		noCipherModeKey.setKeyStartTime(Instant.now());
		noCipherModeKey.setConfiguration(
				Map.of(
						KEY_ENCRYPTION_KEY, WRAPPING_KEY_ID,
						KEY_SIZE, keySize,
						IV_SIZE, TEST_24_IV_BYTES.length,
						CIPHER_ALG, Algorithm.AES,
						CIPHER_MODE, Mode.NONE,
						CIPHER_PADDING, NO_PADDING,
						GCM_TAG_LENGTH, GCM_TAG_LENGTH_VALUE
				)
		);
		cryptoKeys.put(noCipherModeKey.getId(), noCipherModeKey);

		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());

		EncryptionServiceDelegate pbEncryptionService = new Base64EncryptionService();

		EncryptionServiceDelegate cachedWrappedKeyEncryptionService = new CachedWrappedKeyEncryptionService(
				this, cipherTextFormatter
		);

		return new EncryptionService(
				List.of(pbEncryptionService, cachedWrappedKeyEncryptionService), this
		);
	}

	@Test
	void testCachedWrappedKeyEncryptionService() {
// GIVEN
		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());

// WHEN
		new CachedWrappedKeyEncryptionService(
				Duration.ofMillis(250),
				Duration.ofDays(7),
				Duration.ofDays(5),
				this, cipherTextFormatter);

// THEN
		assertThat(getCacheEntryTTL()).isEqualTo(Duration.ofMillis(250));
		assertThat(getCurrentEntryTTL()).isEqualTo(Duration.ofDays(7));
		assertThat(getCacheGracePeriod()).isEqualTo(Duration.ofDays(5));
	}

	@Test
	void validateCreateContentEncryptionParameters() {
		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());
		CachedWrappedKeyEncryptionService es = new CachedWrappedKeyEncryptionService(this, cipherTextFormatter);
		new EncryptionService(
				List.of(es), this
		);

		CryptoKeyConfiguration cep =
				es.createConfigPojo(
						Map.of(
								DATA_ENCRYPTION_KEY, DATA_ENCRYPTION_KEY,
								CIPHER_ALG, Algorithm.AES.getAlgorithm(),
								CIPHER_MODE, GCM.getMode(),
								CIPHER_PADDING, PKCS5_PADDING.getPadding(),
								KEY_SIZE, Integer.toString(TEST_KEY_BYTES.length),
								GCM_TAG_LENGTH, Integer.toString(GCM_TAG_LENGTH_VALUE),
								IV_SIZE, Integer.toString(16)
						),
						CryptoKeyConfiguration.class
				);

		assertThat(cep.algorithm()).isEqualTo(Algorithm.AES);
		assertThat(cep.mode()).isEqualTo(GCM);
		assertThat(cep.padding()).isEqualTo(PKCS5_PADDING);
		assertThat(cep.keySize()).isEqualTo(TEST_KEY_BYTES.length);
		assertThat(cep.gcmTagLength()).isEqualTo(GCM_TAG_LENGTH_VALUE);
		assertThat(cep.ivSize()).isEqualTo(16);
	}

	@Test
	void failHMAC() {
		List<HmacHolder> hmacs = List.of(new HmacHolder(getCurrentEncryptionKey(), "Value to HMAC"));

		assertThrows(UnsupportedOperationException.class, () ->
				encryptionService.hmac(hmacs)
		);
	}

	@Test
	void encryptException() {
		encryptionService = setUp(GCM_CIPHERTEXT_LENGTH_VALUE);
		CryptoKey cryptoKey = getById("AES-CBC");

		assertThrows(NonTransientCryptoException.class, () ->
				encryptionService.encrypt(cryptoKey, data)
		);
	}

	@Test
	void decryptException() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_16_IV_BYTES, TEST_16_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_16_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted = encryptionService.encrypt(cbcCryptoKey, data);

			String encryptedText = new
					CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted)
					.replace(PKCS5_PADDING.getPadding(), "BAD_PADDING");

			assertThrows(NonTransientCryptoException.class, () ->
					encryptionService.decrypt(encryptedText) // mess with the padding
			);
		}
	}

	@Test
	void multiEncryptDecrypt() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted1 = encryptionService.encrypt(getById(AES_GCM_CACHED_WRAPPED_KEY_ID), data);
			CiphertextContainer encrypted2 = encryptionService.encrypt(getById(AES_GCM_CACHED_WRAPPED_KEY_ID), data);
			String decrypted1 = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted1));
			String decrypted2 = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted2));

			assertThat(encrypted1.getCryptoKey()).isEqualTo(aesGCMKey);
			assertThat(encrypted2.getCryptoKey()).isEqualTo(aesGCMKey);

			assertThat(decrypted1).isEqualTo(data);
			assertThat(decrypted2).isEqualTo(data);
		}
	}

	@Test
	void encryptClearCacheDecrypt() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted1 = encryptionService.encrypt(aesGCMKey, data);
			CiphertextContainer encrypted2 = encryptionService.encrypt(aesGCMKey, data);

			clearCache();

			String decrypted1 = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted1));
			String decrypted2 = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted2));

			assertThat(encrypted1.getCryptoKey()).isEqualTo(aesGCMKey);
			assertThat(encrypted2.getCryptoKey()).isEqualTo(aesGCMKey);

			assertThat(decrypted1).isEqualTo(data);
			assertThat(decrypted2).isEqualTo(data);
		}
	}

	@Test
	void encryptGCM() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted = encryptionService.encrypt(aesGCMKey, data);

			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_ALGORITHM_FIELD_NAME, ALGORITHM_VALUE);
			assertThat(encrypted.getData().get(CIPHER_TEXT_FIELD_NAME)).matches(object -> ((String) object).length() == GCM_CIPHERTEXT_LENGTH_VALUE);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_DATA_ENCRYPTION_KEY_FIELD_NAME, "{\"cryptoKeyId\":\"WRAPPING-KEY-ID\",\"data\":{\"cipherText\":\"" + Base64.getEncoder().encodeToString(Base64.getEncoder().encodeToString(getCurrentKey().key()).getBytes()) + "\"}}");
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_DATA_ENCRYPTION_KEY_ID_FIELD_NAME, getCurrentKey().keyId());
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_GCM_TAG_LENGTH_FIELD_NAME, GCM_TAG_LENGTH_VALUE);
			assertThat(encrypted.getData().get(CIPHERTEXT_IV_FIELD_NAME)).matches(encodedIv -> encodedIv.equals(Base64.getEncoder().encodeToString(TEST_24_IV_BYTES)));
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_KEY_SIZE_FIELD_NAME, TEST_KEY_BYTES.length);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_MODE_FIELD_NAME, GCM_MODE_VALUE);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_PADDING_FIELD_NAME, NO_PADDING_VALUE);
			assertThat(encrypted.getCryptoKey()).isEqualTo(aesGCMKey);

// ensure key bytes have been destroyed
			assertThat(isEmpty(keyBytes)).isTrue();

// don't normally use another method to help a test but better to just make sure whatever got encrypted can be decrypted ok too!
			assertThat(encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted))).isEqualTo(data);
		}
	}

	@Test
	void encryptCBC() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_16_IV_BYTES, TEST_16_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_16_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted = encryptionService.encrypt(cbcCryptoKey, data);

			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_ALGORITHM_FIELD_NAME, ALGORITHM_VALUE);
			assertThat(encrypted.getData().get(CIPHER_TEXT_FIELD_NAME)).matches(object -> ((String) object).length() == CBC_CIPHERTEXT_LENGTH_VALUE);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_DATA_ENCRYPTION_KEY_FIELD_NAME, "{\"cryptoKeyId\":\"WRAPPING-KEY-ID\",\"data\":{\"cipherText\":\"" + Base64.getEncoder().encodeToString(Base64.getEncoder().encodeToString(getCurrentKey().key()).getBytes()) + "\"}}");
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_DATA_ENCRYPTION_KEY_ID_FIELD_NAME, getCurrentKey().keyId());
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_GCM_TAG_LENGTH_FIELD_NAME, GCM_TAG_LENGTH_VALUE);
			assertThat(encrypted.getData().get(CIPHERTEXT_IV_FIELD_NAME)).matches(encodedIv -> encodedIv.equals(Base64.getEncoder().encodeToString(TEST_16_IV_BYTES)));
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_KEY_SIZE_FIELD_NAME, TEST_KEY_BYTES.length);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_MODE_FIELD_NAME, CBC_MODE_VALUE);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_PADDING_FIELD_NAME, PKCS5_PADDING_VALUE);
			assertThat(encrypted.getCryptoKey()).isEqualTo(cbcCryptoKey);

// ensure key bytes have been destroyed
			assertThat(isEmpty(keyBytes)).isTrue();

// don't normally use another method to help a test but better to just make sure whatever got encrypted can be decrypted ok too!
			assertThat(encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted))).isEqualTo(data);
		}
	}

	@Test
	void encryptNoCipherMode() {
		assertThrows(NonTransientCryptoException.class, () ->
				encryptionService.encrypt(noCipherModeKey, data));

		assertThatThrownBy(() -> encryptionService.encrypt(noCipherModeKey, data))
				.isInstanceOf(NonTransientCryptoException.class)
				.hasCauseInstanceOf(NoSuchAlgorithmException.class)
				.hasMessage("Configuration error");
	}

	@Test
	void encryptKeyAlreadyDestroyedRaceCondition() throws NoSuchFieldException, IllegalAccessException {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);

// call encrypt first to make sure there's a key in the cache. Need to improve this part of the test by explicitly doing this
			encryptionService.encrypt(aesGCMKey, data);
			destroyCurrentKey();

			CiphertextContainer encrypted = encryptionService.encrypt(aesGCMKey, data);

			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_ALGORITHM_FIELD_NAME, ALGORITHM_VALUE);
			assertThat(encrypted.getData().get(CIPHER_TEXT_FIELD_NAME)).matches(object -> ((String) object).length() == GCM_CIPHERTEXT_LENGTH_VALUE);
			assertThat((String) encrypted.getData().get(CIPHERTEXT_DATA_ENCRYPTION_KEY_FIELD_NAME)).startsWith("{\"cryptoKeyId\":\"" + WRAPPING_KEY_ID + "\",\"data\":{\"cipherText\":\"" + Base64.getEncoder().encodeToString(Base64.getEncoder().encodeToString(currentKeyBytes).getBytes()) + "\"}}");
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_DATA_ENCRYPTION_KEY_ID_FIELD_NAME, getCurrentKey().keyId());
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_GCM_TAG_LENGTH_FIELD_NAME, GCM_TAG_LENGTH_VALUE);
			assertThat(encrypted.getData().get(CIPHERTEXT_IV_FIELD_NAME)).matches(encodedIv -> encodedIv.equals(Base64.getEncoder().encodeToString(TEST_24_IV_BYTES)));
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_KEY_SIZE_FIELD_NAME, TEST_KEY_BYTES.length);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_MODE_FIELD_NAME, GCM_MODE_VALUE);
			assertThat(encrypted.getData()).containsEntry(CIPHERTEXT_PADDING_FIELD_NAME, NO_PADDING_VALUE);
			assertThat(encrypted.getCryptoKey()).isEqualTo(aesGCMKey);

// ensure key bytes have been destroyed
			assertThat(isEmpty(mockedCachedWrappedKeyHolder.key())).isTrue();
// don't normally use another method to help a test but better to just make sure whatever got encrypted can be decrypted ok too!
// first have to reset the key bytes in the cache because encrypt will have destroyed them
			given(mockedCachedWrappedKeyHolder.key()).willReturn(Arrays.copyOf(currentKeyBytes, currentKeyBytes.length));
			assertThat(encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted))).isEqualTo(data);
		}
	}

	@Test
	void decryptKeyNotCached() {
		String finalCiphertext = "{\"cryptoKeyId\":\"AES-GCM\",\"data\":{\"iv\":\"T5SQzYdRswBVbbM3EVXibw==\",\"padding\":\"NoPadding\",\"gcmTagLength\":128,\"mode\":\"GCM\",\"algorithm\":\"AES\",\"cipherText\":\"t6hPLDTAnb/T9nAmR1YCFypmP/+yo9+SkUmT\",\"dek\":\"{\\\"cryptoKeyId\\\":\\\"WRAPPING-KEY-ID\\\",\\\"data\\\":{\\\"cipherText\\\":\\\"d0JBUHFoVHpJR0FQSTFPR1RnZVVRZjIrZ2g4cmdnOHRraDdCMGdUbW1kOD0=\\\"}}\",\"dekId\":\"07b43c15-e964-476c-9133-915dea6ee67f\",\"keySize\":256}}";

		String decrypted = encryptionService.decrypt(finalCiphertext);

		assertThat(decrypted).isEqualTo(data);
	}

	@Test
	void decryptKeyAlreadyCached() {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);
// creates a new key and puts it in the cache
			CiphertextContainer encrypted = encryptionService.encrypt(aesGCMKey, data);
			String decrypted = encryptionService.decrypt(
					new CiphertextFormatter(this, new ConfigurableObjectMapperFactory())
							.format(encrypted));

			assertThat(decrypted).isEqualTo(data);

// ensure key bytes have been destroyed
			assertThat(isEmpty(keyBytes)).isTrue();
		}
	}

	@Test
	void decryptKeyAlreadyDestroyedRaceCondition() throws NoSuchFieldException, IllegalAccessException {
		byte[] keyBytes = Arrays.copyOf(TEST_KEY_BYTES, TEST_KEY_BYTES.length);
		byte[] ivBytes = Arrays.copyOf(TEST_24_IV_BYTES, TEST_24_IV_BYTES.length);
		try (MockedStatic<Generators> mockedGenerator = mockStatic(Generators.class)) {
			mockedGenerator.when(() -> Generators.generateRandomBits(TEST_KEY_BYTES.length)).thenReturn(keyBytes);
			mockedGenerator.when(() -> Generators.generateIV(TEST_24_IV_BYTES.length)).thenReturn(ivBytes);

			CiphertextContainer encrypted = encryptionService.encrypt(aesGCMKey, data);
			destroyCurrentKey();
			String decrypted = encryptionService.decrypt(
					new CiphertextFormatter(this, new ConfigurableObjectMapperFactory())
							.format(encrypted));

			assertThat(decrypted).isEqualTo(data);

// ensure key bytes have been destroyed
			assertThat(isEmpty(keyBytes)).isTrue();
		}
	}

	@SuppressWarnings({"rawtypes", "unchecked"})
	private void destroyCurrentKey() throws NoSuchFieldException, IllegalAccessException {
		ConcurrentCache cachedWrappedKeyHolderConcurrentCache = getConcurrentCache();
		Field currentEntryField = cachedWrappedKeyHolderConcurrentCache.getClass().getDeclaredField("currentEntry");
		currentEntryField.setAccessible(true);
		AtomicReference currentEntry = (AtomicReference) currentEntryField.get(cachedWrappedKeyHolderConcurrentCache);
		String cacheCurrentKeyId = (String) ((Map.Entry) currentEntry.get()).getKey();

		CachedWrappedKeyHolder actualCurrentKey = getCurrentKey();
// store a copy of this for later because CachedWrappedKeyEncryptionService destroys these key byte arrays
		currentKeyBytes = Arrays.copyOf(actualCurrentKey.key(), actualCurrentKey.key().length);

		mockedCachedWrappedKeyHolder = Mockito.mock(CachedWrappedKeyHolder.class);
		given(mockedCachedWrappedKeyHolder.key()).willThrow(new KeyAlreadyDestroyedException()).willReturn(Arrays.copyOf(currentKeyBytes, currentKeyBytes.length));
		given(mockedCachedWrappedKeyHolder.persistableEncryptedKey()).willReturn(actualCurrentKey.persistableEncryptedKey());
		given(mockedCachedWrappedKeyHolder.keyId()).willReturn(actualCurrentKey.keyId());
		cachedWrappedKeyHolderConcurrentCache.putCurrent(cacheCurrentKeyId, mockedCachedWrappedKeyHolder);
	}

	private CachedWrappedKeyHolder getCurrentKey() {
		return getConcurrentCache().getCurrent();
	}

	@SuppressWarnings("unchecked")
	private ConcurrentCache<String, CachedWrappedKeyHolder> getConcurrentCache() {
		try {
			Field cachedWrappedKeyHolderConcurrentCacheField = CachedWrappedKeyEncryptionService.class.getDeclaredField("CACHED_WRAPPED_KEY_HOLDER_CONCURRENT_CACHE");
			cachedWrappedKeyHolderConcurrentCacheField.setAccessible(true);
			return ((ConcurrentCache<String, CachedWrappedKeyHolder>) cachedWrappedKeyHolderConcurrentCacheField.get(null));
		} catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	private void clearCache() {
		getConcurrentCache().clear();
	}

	private Duration getCacheEntryTTL() {
		return getConcurrentCache().getCacheEntryTTL();
	}

	private Duration getCurrentEntryTTL() {
		return getConcurrentCache().getCurrentEntryTTL();
	}

	private Duration getCacheGracePeriod() {
		return getConcurrentCache().getCacheGracePeriod();
	}
}