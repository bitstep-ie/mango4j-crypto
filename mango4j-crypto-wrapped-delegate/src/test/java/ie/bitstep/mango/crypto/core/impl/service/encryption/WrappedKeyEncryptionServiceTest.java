package ie.bitstep.mango.crypto.core.impl.service.encryption;

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
import ie.bitstep.mango.crypto.core.enums.Padding;
import ie.bitstep.mango.crypto.core.enums.WrappedCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.exceptions.UnsupportedKeyTypeException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.impl.service.encryption.CipherConfig;
import ie.bitstep.mango.crypto.core.impl.service.encryption.CipherManager;
import ie.bitstep.mango.crypto.core.impl.service.encryption.CryptoKeyConfiguration;
import ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedKeyEncryptionService;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.core.utils.Generators;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class WrappedKeyEncryptionServiceTest implements CryptoKeyProvider {
	private final String data = "hello dolly";
	private final Map<String, CryptoKey> cryptoKeys = new HashMap<>();

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
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId("4e230ee3-90a5-4e4c-b000-9fe8be53c7cd");
		cryptoKey.setType(NonProdCryptoKeyTypes.BASE_64.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setKeyStartTime(Instant.now());
		cryptoKeys.put(cryptoKey.getId(), cryptoKey);

		cryptoKey = new CryptoKey();
		cryptoKey.setId("AES-CBC");
		cryptoKey.setType(WrappedCryptoKeyTypes.WRAPPED.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setKeyStartTime(Instant.now());
		cryptoKey.setConfiguration(
			Map.of(
				KEY_ENCRYPTION_KEY, "4e230ee3-90a5-4e4c-b000-9fe8be53c7cd",
				KEY_SIZE, keySize,
				IV_SIZE, 16,
				CIPHER_ALG, Algorithm.AES,
				CIPHER_MODE, CBC,
				CIPHER_PADDING, PKCS5_PADDING,
				GCM_TAG_LENGTH, 128
			)
		);
		cryptoKeys.put(cryptoKey.getId(), cryptoKey);

		cryptoKey = new CryptoKey();
		cryptoKey.setId("AES-GCM");
		cryptoKey.setType(WrappedCryptoKeyTypes.WRAPPED.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setKeyStartTime(Instant.now());
		cryptoKey.setConfiguration(
			Map.of(
				KEY_ENCRYPTION_KEY, "4e230ee3-90a5-4e4c-b000-9fe8be53c7cd",
				KEY_SIZE, keySize,
				IV_SIZE, 16,
				CIPHER_ALG, Algorithm.AES,
				CIPHER_MODE, GCM,
				CIPHER_PADDING, NO_PADDING,
				GCM_TAG_LENGTH, 128
			)
		);
		cryptoKeys.put(cryptoKey.getId(), cryptoKey);

		cryptoKey = new CryptoKey();
		cryptoKey.setId("AES-NONE");
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setKeyStartTime(Instant.now());
		cryptoKey.setConfiguration(
			Map.of(
				KEY_ENCRYPTION_KEY, "4e230ee3-90a5-4e4c-b000-9fe8be53c7cd",
				KEY_SIZE, keySize,
				IV_SIZE, 16,
				CIPHER_ALG, Algorithm.AES,
				CIPHER_MODE, Mode.NONE,
				CIPHER_PADDING, NO_PADDING,
				GCM_TAG_LENGTH, 128
			)
		);
		cryptoKeys.put(cryptoKey.getId(), cryptoKey);

		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());

		EncryptionServiceDelegate pbEncryptionService = new Base64EncryptionService();

		EncryptionServiceDelegate wrappedKeyEncryptionService = new WrappedKeyEncryptionService(
			this, cipherTextFormatter
		);

		return new EncryptionService(
			List.of(pbEncryptionService, wrappedKeyEncryptionService), this
		);
	}

	@Test
	void initCipherModeNone() throws NoSuchPaddingException, NoSuchAlgorithmException {
		Cipher cipher = CipherManager.getCipherInstance(Algorithm.AES, Mode.GCM, NO_PADDING);
		CipherConfig cipherConfig = new CipherConfig(
			Algorithm.AES,
			Mode.NONE,
			NO_PADDING,
			128
		);

		assertDoesNotThrow(() ->
			CipherManager.initCipher(
				Cipher.ENCRYPT_MODE,
				cipherConfig,
				new byte[0],
				cipher,
				WrappedKeyEncryptionService.generateDataEncryptionKey(256, cipherConfig)
			)
		);
	}

	@ParameterizedTest
	@ValueSource(strings = {"AES/GCM/NoPadding", "AES/CBC/PKCS5Padding"})
	void initCipherModes(String spec) throws NoSuchPaddingException, NoSuchAlgorithmException {
		String[] cipherSpec = spec.split("/");
		Algorithm algorithm = Algorithm.fromValue(cipherSpec[0]);
		Mode mode = Mode.fromValue(cipherSpec[1]);
		Padding padding = Padding.fromValue(cipherSpec[2]);
		Cipher cipher = CipherManager.getCipherInstance(algorithm, mode, padding);
		CipherConfig cipherConfig = new CipherConfig(
			algorithm,
			mode,
			padding,
			128
		);

		assertDoesNotThrow(() ->
			CipherManager.initCipher(
				Cipher.ENCRYPT_MODE,
				cipherConfig,
				Generators.generateIV(16),
				cipher,
				WrappedKeyEncryptionService.generateDataEncryptionKey(256, cipherConfig)
			)
		);
	}

	@Test
	void validateCreateContentEncryptionParameters() {
		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());
		WrappedKeyEncryptionService es = new WrappedKeyEncryptionService(this, cipherTextFormatter);
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
					KEY_SIZE, Integer.toString(256),
					GCM_TAG_LENGTH, Integer.toString(128),
					IV_SIZE, Integer.toString(16)
				),
				CryptoKeyConfiguration.class
			);

		assertThat(cep.algorithm()).isEqualTo(Algorithm.AES);
		assertThat(cep.mode()).isEqualTo(GCM);
		assertThat(cep.padding()).isEqualTo(PKCS5_PADDING);
		assertThat(cep.keySize()).isEqualTo(256);
		assertThat(cep.gcmTagLength()).isEqualTo(128);
		assertThat(cep.ivSize()).isEqualTo(16);
	}

	@Test
	void failHMAC() {
		EncryptionService encryptionService = setUp(256);
		List<HmacHolder> hmacs = List.of(new HmacHolder(getCurrentEncryptionKey(), "Value to HMAC"));

		assertThrows(UnsupportedOperationException.class, () ->
			encryptionService.hmac(hmacs)
		);
	}

	@Test
	void encryptException() {
		EncryptionService encryptionService = setUp(36);
		CryptoKey cryptoKey = getById("AES-CBC");

		assertThrows(NonTransientCryptoException.class, () ->
			encryptionService.encrypt(cryptoKey, data)
		);
	}

	@Test
	void decryptException() {
		EncryptionService encryptionService = setUp(256);
		CiphertextContainer encrypted = encryptionService.encrypt(getById("AES-CBC"), data);

		String encryptedText = new
			CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted)
			.replace(PKCS5_PADDING.getPadding(), "BAD_PADDING");

		assertThrows(NonTransientCryptoException.class, () ->
			encryptionService.decrypt(encryptedText) // mess with the padding
		);
	}

	@Test
	void encryptCBC() {
		EncryptionService encryptionService = setUp(256);
		CiphertextContainer encrypted = encryptionService.encrypt(getById("AES-CBC"), data);

		assertThat(encrypted.getCryptoKey()).isEqualTo(getById("AES-CBC"));
	}

	@Test
	void decryptCBC() {
		EncryptionService encryptionService = setUp(256);
		CiphertextContainer encrypted = encryptionService.encrypt(getById("AES-CBC"), data);
		String decrypted = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted));

		assertThat(decrypted).isEqualTo(data);
	}

	@Test
	void encryptGCM() {
		EncryptionService encryptionService = setUp(256);
		CiphertextContainer encrypted = encryptionService.encrypt(getById("AES-GCM"), data);

		assertThat(encrypted.getCryptoKey()).isEqualTo(getById("AES-GCM"));
	}

	@Test
	void decryptGCM() {
		EncryptionService encryptionService = setUp(256);
		CiphertextContainer encrypted = encryptionService.encrypt(getById("AES-GCM"), data);
		String decrypted = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted));

		assertThat(decrypted).isEqualTo(data);
	}

	@Test
	void encryptNONE() {
		EncryptionService encryptionService = setUp(256);
		CryptoKey cryptoKey = getById("AES-NONE");

		assertThrows(UnsupportedKeyTypeException.class, () ->
			encryptionService.encrypt(cryptoKey, data)
		);
	}
}