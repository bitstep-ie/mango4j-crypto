package ie.bitstep.mango.crypto.core.impl.service.encryption;

import ie.bitstep.mango.crypto.core.enums.Algorithm;
import ie.bitstep.mango.crypto.core.enums.Mode;
import ie.bitstep.mango.crypto.core.enums.Padding;

/**
 * Configuration holder for cipher operations.
 * <p>
 * Encapsulates the algorithm, mode, padding, and GCM tag length used for encryption/decryption.
 *
 * @param algorithm    the cryptographic algorithm to use (e.g., AES)
 * @param mode         the cipher mode of operation (e.g., CBC, GCM)
 * @param padding      the padding scheme to apply (e.g., PKCS5Padding)
 * @param gcmTagLength the length (in bits) of the authentication tag for GCM mode
 */
public record CipherConfig(
	Algorithm algorithm,
	Mode mode,
	Padding padding,
	int gcmTagLength) {

	/**
	 * Creates a cipher config from a crypto key configuration.
	 *
	 * @param cep the crypto key configuration
	 * @return the cipher config
	 */
	static CipherConfig of(CryptoKeyConfiguration cep) {
		return new CipherConfig(
			cep.algorithm(),
			cep.mode(),
			cep.padding(),
			cep.gcmTagLength()
		);
	}

	/**
	 * Creates a cipher config from encrypted data configuration.
	 *
	 * @param edc the encrypted data configuration
	 * @return the cipher config
	 */
	static CipherConfig of(EncryptedDataConfig edc) {
		return new CipherConfig(
			edc.algorithm(),
			edc.mode(),
			edc.padding(),
			edc.gcmTagLength()
		);
	}
}
