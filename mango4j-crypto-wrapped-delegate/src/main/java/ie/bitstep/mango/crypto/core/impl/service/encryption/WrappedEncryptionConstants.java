package ie.bitstep.mango.crypto.core.impl.service.encryption;

/**
 * Constants used by wrapped encryption implementations.
 */
public class WrappedEncryptionConstants {
	/**
	 * Prevents instantiation.
	 */
	private WrappedEncryptionConstants() {

	}

	public static final String CONFIGURATION_ERROR = "Configuration error";
	public static final String CIPHER_TEXT = "cipherText";
	public static final String DATA_ENCRYPTION_KEY = "dek";
	public static final String KEY_ENCRYPTION_KEY = "kek";
	public static final String DATA_ENCRYPTION_KEY_ID = "dekId";
	public static final String GCM_TAG_LENGTH = "gcmTagLength";
	public static final String IV = "iv";
	public static final String CIPHER_ALG = "algorithm";
	public static final String CIPHER_MODE = "mode";
	public static final String CIPHER_PADDING = "padding";
	public static final String KEY_SIZE = "keySize";
	public static final String IV_SIZE = "ivSize";
}
