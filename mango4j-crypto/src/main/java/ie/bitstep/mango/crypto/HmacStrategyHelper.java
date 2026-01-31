package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;

/**
 * Helper container for dependencies needed by HMAC strategies.
 *
 * @param encryptionService the encryption service used to compute HMACs
 * @param cryptoKeyProvider the key provider used to resolve HMAC keys
 */
public record HmacStrategyHelper(EncryptionService encryptionService, CryptoKeyProvider cryptoKeyProvider) {
}
