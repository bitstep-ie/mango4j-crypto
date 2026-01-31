package ie.bitstep.mango.crypto.core.providers;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.List;

/**
 * Interface used by the library to retrieve {@link CryptoKey keys} for decryption operations.
 */
public interface CryptoKeyProvider {
	/**
	 * Applications manage their own {@link CryptoKey keys} and so must be able to return
	 * {@link CryptoKey keys} to this library when asked.
	 *
	 * @param cryptoKeyId The ID of the key to find
	 * @return A {@link CryptoKey} object. <b>Cannot be null</b>. If this returns null the library will throw an error.
	 */
	CryptoKey getById(String cryptoKeyId);

	/**
	 *
	 * @return The {@link CryptoKey encryption key} that should be used for the current cryptographic operation.
	 * Most likely this will be the encryption key that the current tenant (in your application request context) is
	 * currently using.
	 */
	CryptoKey getCurrentEncryptionKey();

	/**
	 *
	 * @return A list of {@link CryptoKey HMAC keys} that should be used for the current cryptographic operation.
	 * Most likely this will be the HMAC keys that the current tenant (in your application request context) is
	 * currently using.
	 */
	List<CryptoKey> getCurrentHmacKeys();

	/**
	 * Only used by automatic background re-key tasks to figure out which {@link CryptoKey CryptoKeys} are being keyed-off or keyed-on.
	 * If your application does not use re-key functionality then this method can just return an empty list.
	 * @return All {@link CryptoKey CryptoKeys} in the system
	 */
	List<CryptoKey> getAllCryptoKeys();

}