package ie.bitstep.mango.crypto.core.impl.service.encryption;

import ie.bitstep.mango.crypto.core.enums.Algorithm;
import ie.bitstep.mango.crypto.core.enums.Mode;
import ie.bitstep.mango.crypto.core.enums.Padding;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CipherManager {
	/**
	 * Prevents instantiation.
	 */
	private CipherManager() {
		// NOSONAR
	}

	/**
	 * Initializes a cipher with the configured parameters.
	 *
	 * @param encryptMode the cipher mode (encrypt/decrypt)
	 * @param cep the cipher configuration
	 * @param iv the initialization vector
	 * @param cipher the cipher instance
	 * @param dek the data encryption key
	 * @throws InvalidKeyException when the key is invalid
	 * @throws InvalidAlgorithmParameterException when parameters are invalid
	 */
	static void initCipher(int encryptMode, CipherConfig cep, byte[] iv, Cipher cipher, SecretKey dek) throws InvalidKeyException, InvalidAlgorithmParameterException {
		switch (cep.mode()) {
			case GCM -> {
				final var gcmSpec = new GCMParameterSpec(cep.gcmTagLength(), iv);
				cipher.init(encryptMode, dek, gcmSpec);
			}

			case CBC -> {
				final var ivSpec = new IvParameterSpec(iv);
				cipher.init(encryptMode, dek, ivSpec);
			}

			case NONE -> { // NOSONAR: DO NOTHING, special mode for testing failure scenarios
			}
		}
	}

	/**
	 * Creates a cipher instance from algorithm parameters.
	 *
	 * @param algorithm the algorithm
	 * @param mode the mode
	 * @param padding the padding
	 * @return the cipher instance
	 * @throws NoSuchPaddingException when padding is not available
	 * @throws NoSuchAlgorithmException when algorithm is not available
	 */
	static Cipher getCipherInstance(Algorithm algorithm, Mode mode, Padding padding) throws NoSuchPaddingException, NoSuchAlgorithmException {
		return Cipher.getInstance(algorithm.getAlgorithm() + "/" + mode.getMode() + "/" + padding.getPadding());
	}

	/**
	 * Creates a cipher instance from cipher configuration.
	 *
	 * @param cc the cipher configuration
	 * @return the cipher instance
	 * @throws NoSuchPaddingException when padding is not available
	 * @throws NoSuchAlgorithmException when algorithm is not available
	 */
	static Cipher getCipherInstance(CipherConfig cc) throws NoSuchPaddingException, NoSuchAlgorithmException {
		return getCipherInstance(cc.algorithm(), cc.mode(), cc.padding());
	}
}
