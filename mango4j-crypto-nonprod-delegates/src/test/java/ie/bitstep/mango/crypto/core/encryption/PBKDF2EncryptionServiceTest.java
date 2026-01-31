package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.enums.Algorithm;
import ie.bitstep.mango.crypto.core.enums.Mode;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.enums.Padding;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import ie.bitstep.mango.crypto.core.formatters.CiphertextFormatter;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class PBKDF2EncryptionServiceTest implements CryptoKeyProvider {
	CryptoKey cryptoKey = new CryptoKey();

	@Override
	public CryptoKey getById(String s) {
		return cryptoKey;
	}

	@Override
	public CryptoKey getCurrentEncryptionKey() {
		return cryptoKey;
	}

	@Override
	public List<CryptoKey> getCurrentHmacKeys() {
		return List.of();
	}

	@Override
	public List<CryptoKey> getAllCryptoKeys() {
		return List.of(cryptoKey);
	}

	private EncryptionServiceDelegate pbEncryptionService;

	EncryptionService setup(
			int keySize,
			int iterations,
			int ivSize,
			Algorithm algorithm,
			Mode mode,
			Padding padding,
			int gcmTagLength) {
		cryptoKey.setId("4e230ee3-90a5-4e4c-b000-9fe8be53c7cd");
		cryptoKey.setConfiguration(
				Map.of(
						PBKDF2EncryptionService.KEY_SIZE, keySize,
						PBKDF2EncryptionService.CIPHER_ALG, algorithm.getAlgorithm(),
						PBKDF2EncryptionService.CIPHER_MODE, mode.getMode(),
						PBKDF2EncryptionService.CIPHER_PADDING, padding.getPadding(),
						PBKDF2EncryptionService.ITERATIONS, iterations,
						PBKDF2EncryptionService.GCM_TAG_LENGTH, gcmTagLength,
						PBKDF2EncryptionService.KEY_ALIAS, "This ia a test key",
						PBKDF2EncryptionService.PASS_PHRASE, "PBKDF2 Test Pass Phrase",
						PBKDF2EncryptionService.HASH_SALT, "PBKDF2 Test Salt",
						PBKDF2EncryptionService.IV_SIZE, ivSize
				)
		);
		cryptoKey.setType(NonProdCryptoKeyTypes.PBKDF2.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setKeyStartTime(Instant.now());

		pbEncryptionService = new PBKDF2EncryptionService();

// specify an object mapper factory up to 100MB to allow large blob test to pass
		return new EncryptionService(
				List.of(pbEncryptionService),
				this,
				new ConfigurableObjectMapperFactory().setMaxStringLength(1024 * 1024 * 100)
		);
	}

	@Test
	void failEncryptInvalidSettings() {
		EncryptionService encryptionService = setup(
				48,
				1000,
				16,
				Algorithm.AES,
				Mode.GCM,
				Padding.NO_PADDING,
				128
		);

		assertThrows(NonTransientCryptoException.class, () ->
				encryptionService.encrypt(cryptoKey, "dummy")
		);
	}

	@Test
	void generatePBKDF2Key() {
		setup(
				256,
				1000,
				16,
				Algorithm.AES,
				Mode.GCM,
				Padding.NO_PADDING,
				128
		);

		final PBKDF2EncryptionService.CryptoKeyConfiguration encryptionConfig = pbEncryptionService.createConfigPojo(getCurrentEncryptionKey(), PBKDF2EncryptionService.CryptoKeyConfiguration.class);

		assertDoesNotThrow(() ->
				PBKDF2EncryptionService.generatePBKDF2Key(
						256,
						1000,
						Algorithm.AES.getAlgorithm(),
						encryptionConfig,
						"SALT".getBytes(StandardCharsets.UTF_8))
		);
	}

	@Test
	void failDencryptInvalidSettings() {
		EncryptionService encryptionService = setup(
				256,
				1000,
				16,
				Algorithm.AES,
				Mode.GCM,
				Padding.NO_PADDING,
				128
		);

		CryptoKey currentEncryptionKey = getCurrentEncryptionKey();

		CiphertextContainer ciphertextContainer = encryptionService.encrypt(currentEncryptionKey, "dummy");
		Map<String, Object> hackedData = new HashMap<>(ciphertextContainer.getData());
		CiphertextContainer hackedCiphertextContainer = new CiphertextContainer(
				ciphertextContainer.getCryptoKey(), hackedData
		);
		CiphertextFormatter cipherTextFormatter = new CiphertextFormatter(this, new ConfigurableObjectMapperFactory());

		hackedCiphertextContainer.getData().put(PBKDF2EncryptionService.CIPHER_MODE, Mode.NONE.getMode());
		String cipherText = cipherTextFormatter.format(hackedCiphertextContainer);

		assertThrows(NonTransientCryptoException.class, () ->
				encryptionService.decrypt(cipherText)
		);
	}

	@Test
	void testHMAC() {
		EncryptionService encryptionService = setup(
				256,
				1000,
				16,
				Algorithm.AES,
				Mode.GCM,
				Padding.NO_PADDING,
				128
		);

		List<HmacHolder> hmacs = List.of(new HmacHolder(getCurrentEncryptionKey(), "Value to HMAC"));

		assertDoesNotThrow(() ->
				encryptionService.hmac(hmacs)
		);

		assertThat(hmacs.get(0).getValue())
				.isNotBlank()
				.isNotEqualTo("Value to HMAC");
	}

	@ParameterizedTest
	@MethodSource("encryptionTestCases")
	void testEncryption(
			String plaintext,
			int keySize,
			int iterations,
			int ivLength,
			Algorithm algorithm,
			Mode mode,
			Padding padding,
			int gcmTagLength) {

		EncryptionService encryptionService = setup(
				keySize,
				iterations,
				ivLength,
				algorithm,
				mode,
				padding,
				gcmTagLength
		);

// Encrypt
		CiphertextContainer encrypted = encryptionService.encrypt(cryptoKey, plaintext);

// create invalid encryption service to ensure decrypt sets all params
		encryptionService = setup(
				-1,
				-1,
				-1,
				Algorithm.NONE,
				Mode.NONE,
				Padding.NONE,
				-1
		);


// Decrypt
		String decryptedText = encryptionService.decrypt(new CiphertextFormatter(this, new ConfigurableObjectMapperFactory()).format(encrypted));

// Verify
		assertEquals(plaintext, decryptedText, "Decryption should return the original plaintext");
	}

	// Provide test cases as a stream
	private static Stream<Arguments> encryptionTestCases() {
		return Stream.of(
				Arguments.of(
						"Hello, Dolly",
						256,
						10000,
						16,
						Algorithm.AES,
						Mode.GCM,
						Padding.NO_PADDING,
						128
				),
				Arguments.of(
						bigString(1024 * 1024 * 50),
						256,
						10000,
						16,
						Algorithm.AES,
						Mode.GCM,
						Padding.NO_PADDING,
						128
				),
				Arguments.of(
						"Hello, Dolly",
						256,
						15000,
						16,
						Algorithm.AES,
						Mode.CBC,
						Padding.PKCS5_PADDING,
						128
				),
				Arguments.of(
						"Hello, Dolly",
						64,
						8000,
						8,
						Algorithm.DES,
						Mode.CBC,
						Padding.PKCS5_PADDING,
						128
				)
		);
	}

	private static String bigString(int size) {
		StringBuilder sb = new StringBuilder();

		while (sb.length() < size) {
			sb.append("**BIG STRING**;");
		}

		return sb.toString();
	}
}