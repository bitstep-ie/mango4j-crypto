package ie.bitstep.mango.crypto.core.impl.service.encryption;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import ie.bitstep.mango.crypto.core.enums.Algorithm;
import ie.bitstep.mango.crypto.core.enums.Mode;
import ie.bitstep.mango.crypto.core.enums.Padding;

import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_ALG;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_MODE;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.CIPHER_PADDING;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.GCM_TAG_LENGTH;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.IV_SIZE;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.KEY_ENCRYPTION_KEY;
import static ie.bitstep.mango.crypto.core.impl.service.encryption.WrappedEncryptionConstants.KEY_SIZE;

/**
 * Configuration for key encryption parameters.
 *
 * @param keyEncryptionKey the wrapping key identifier or material
 * @param keySize          the key size in bits
 * @param ivSize           the IV size in bytes
 * @param algorithm        the cipher algorithm
 * @param mode             the cipher mode
 * @param padding          the cipher padding
 * @param gcmTagLength     the GCM tag length in bits
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CryptoKeyConfiguration(
	@JsonProperty(KEY_ENCRYPTION_KEY)
	String keyEncryptionKey,
	@JsonProperty(KEY_SIZE)
	int keySize,
	@JsonProperty(IV_SIZE)
	int ivSize,
	@JsonProperty(CIPHER_ALG)
	Algorithm algorithm,
	@JsonProperty(CIPHER_MODE)
	Mode mode,
	@JsonProperty(CIPHER_PADDING)
	Padding padding,
	@JsonProperty(GCM_TAG_LENGTH)
	int gcmTagLength) {
}
