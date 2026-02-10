package ie.bitstep.mango.crypto.core.enums;

/**
 * Implementations that are supported natively by this library.
 */
public enum WrappedCryptoKeyTypes { // NOSONAR: Single crypto key type supported
	WRAPPED,
	CACHED_WRAPPED;

	/**
	 * Returns the enum name for this key type.
	 *
	 * @return the key type name
	 */
	public String getName() {
		return this.name();
	}
}
