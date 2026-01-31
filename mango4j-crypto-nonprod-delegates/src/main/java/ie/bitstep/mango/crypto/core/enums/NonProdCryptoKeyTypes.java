package ie.bitstep.mango.crypto.core.enums;

/**
 * Implementations that are supported natively by this library.
 */
public enum NonProdCryptoKeyTypes {
	BASE_64,
	PBKDF2,
	IDENTITY;

	/**
	 * Returns the enum name for this key type.
	 *
	 * @return the key type name
	 */
	public String getName() {
		return this.name();
	}
}
