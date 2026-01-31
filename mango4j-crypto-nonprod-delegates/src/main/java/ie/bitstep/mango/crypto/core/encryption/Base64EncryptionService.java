package ie.bitstep.mango.crypto.core.encryption;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.enums.NonProdCryptoKeyTypes;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;

/**
 * Dummy class to be used for testing/demo/local development purposes only.
 */
public class Base64EncryptionService extends EncryptionServiceDelegate {
	private static final Base64.Decoder DECODER = Base64.getDecoder();
	private static final Base64.Encoder ENCODER = Base64.getEncoder();
	private static final String CIPHER_TEXT = "cipherText";

	/**
	 * Just returns the base64 encoded value of {@code data}
	 *
	 * @param encryptionKey crypto key to use for encryption (not used in this dummy implementation)
	 * @param data          data to encrypt
	 * @return {@link CiphertextContainer} representing the base64 encoded data.
	 */
	@Override
	public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
		return new CiphertextContainer(encryptionKey, Map.of(CIPHER_TEXT, base64Encode(data)));
	}

	/**
	 * Encodes the supplied value with Base64.
	 *
	 * @param data the input data
	 * @return the base64-encoded string
	 */
	private String base64Encode(String data) {
		return new String(ENCODER.encode(data.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
	}

	/**
	 * Decodes a Base64-encoded value.
	 *
	 * @param ciphertextContainer the ciphertext container
	 * @return the decoded plaintext
	 */
	@Override
	public String decrypt(CiphertextContainer ciphertextContainer) {
		return new String(DECODER.decode(((String) ciphertextContainer.getData().get(CIPHER_TEXT)).getBytes(StandardCharsets.UTF_8)),
			StandardCharsets.UTF_8);
	}

	/**
	 * Computes Base64 HMAC placeholders for the supplied holders.
	 *
	 * @param hmacHolders the holders to update
	 */
	@Override
	public void hmac(Collection<HmacHolder> hmacHolders) {
		hmacHolders.forEach(hmacHolder -> hmacHolder.setValue(base64Encode(hmacHolder.getCryptoKey().getId() + ":" + hmacHolder.getValue())));
	}

	/**
	 * Returns the supported crypto key type.
	 *
	 * @return the key type name
	 */
	@Override
	public String supportedCryptoKeyType() {
		return NonProdCryptoKeyTypes.BASE_64.getName();
	}
}
