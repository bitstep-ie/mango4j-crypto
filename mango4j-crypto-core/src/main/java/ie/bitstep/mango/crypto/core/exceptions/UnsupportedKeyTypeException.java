package ie.bitstep.mango.crypto.core.exceptions;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

/**
 * Exception thrown if an application tried to use a {@link CryptoKey} with a
 * that this library doesn't support
 */
public class UnsupportedKeyTypeException extends NonTransientCryptoException {

	/**
	 * Creates an exception for an unsupported crypto key type.
	 *
	 * @param cryptoKey the crypto key
	 */
	public UnsupportedKeyTypeException(CryptoKey cryptoKey) {
		// Not copying the key material into the message in case some types of [future] crypto keys have sensitive key material
		super(String.format("No Encryption Service was registered for crypto key [id:%s, type:%s, usage:%s]",
				cryptoKey.getId(), cryptoKey.getType() == null ? null : cryptoKey.getType(), cryptoKey.getUsage()));
	}
}
