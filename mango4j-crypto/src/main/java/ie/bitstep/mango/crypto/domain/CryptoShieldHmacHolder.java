package ie.bitstep.mango.crypto.domain;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;

import java.util.Objects;

/**
 * Please read the official documentation for this library to understand why we use this class.
 */
public final class CryptoShieldHmacHolder {

	/**
	 * {@link CryptoKey} to be used for calculating the HMAC.
	 */
	private String cryptoKeyId;

	/**
	 * Data to calculate the HMAC for.
	 * <br>
	 * {@link EncryptionService#hmac(java.util.Collection)
	 * EncryptionService#hmac(Collection<HmacHolder> hmacHolders)} will overwrite this field with the result of the
	 * HMAC operation.
	 */
	private String value;

	/**
	 * Optional value which can be set by applications. This is necessary to facilitate HMAC service implementations which
	 * can call an external cryptographic providers batch HMAC call. i.e. Some cryptographic services offer an endpoint which accepts
	 * multiple values to HMAC in the body so applications can calculate the HMACs for multiple values with a single call.
	 * However, these
	 * types of operations need each value to be accompanied by an associated alias for the value so that applications
	 * can tell which HMAC values in the response correspond to which input values. It is encouraged that applications
	 * collect all values from their data model that they need to HMAC into a single list and call
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection)}
	 * only once for better performance. Rather than calling
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection)}
	 * to HMAC the PAN list, then calling it again to HMAC the username list, etc. (remember each field generates a list of
	 * {@link CryptoShieldHmacHolder HMAC holders} to accommodate key rotation).
	 * <p>
	 * Bundle them all into one list setting this field
	 * on each one to an appropriate value and make a single call. If this field isn't set then an application must call
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection)}
	 * for each field value they need to HMAC, which may not allow for the best performance (depending on the underlying
	 * {@link EncryptionService EncryptionService}) implementation.
	 * </p>
	 */
	private final String hmacAlias;

	/**
	 * Optional value which can be set by applications. This is necessary to facilitate supporting HMAC field tokenizers
	 * which generate potentially multiple HMACs for a single value by calculated HMACs for different parts of the value or
	 * generating multiple HMACs for different representations of the value. i.e. if using mango4j-crypto library and an
	 * application with a field annotated with @Hmac has a 'PanTokenizer' specified then when CryptoShield.encrypt(Object)
	 * is called this library would generate the HMAC of the original PAN value, a HMAC of the PAN value with dashes removed
	 * and a HMAC of the last 4 digits of the PAN to facilitate more flexible search capabilities on the PAN field.
	 * In this case each {@link CryptoShieldHmacHolder} needs to document which HMAC it actually corresponds to (since the hmacAlias
	 * field would have the same value, 'pan' or whatever and would no longer not be enough to tell them apart) so it can
	 * use this field to do that. i.e. for the above example the PanTokenizer would set this field to 'last4Digits' for
	 * the HMAC which was generated for the last 4 digits of the pan and set this field to 'withoutDashes' for the HMAC
	 * which was generated for the PAN with the dashes removed. Having this field set to helpful values when using
	 * tokenizers might help for application search functions. If an application doesn't use tokenizers on any HMAC
	 * fields then this field can be left blank as it would serve no purpose.
	 */
	private final String tokenizedRepresentation;

	/**
	 * Creates a holder with a key ID and value.
	 *
	 * @param cryptoKeyId the crypto key ID
	 * @param valueToHmac the value to HMAC
	 */
	public CryptoShieldHmacHolder(String cryptoKeyId, String valueToHmac) {
		this(cryptoKeyId, valueToHmac, null);
	}

	/**
	 * Creates a holder with key ID, value, and alias.
	 *
	 * @param cryptoKeyId the crypto key ID
	 * @param valueToHmac the value to HMAC
	 * @param hmacAlias the HMAC alias
	 */
	public CryptoShieldHmacHolder(String cryptoKeyId, String valueToHmac, String hmacAlias) {
		this(cryptoKeyId, valueToHmac, hmacAlias, null);
	}

	/**
	 * Creates a holder with key ID, value, alias, and representation.
	 *
	 * @param cryptoKeyId the crypto key ID
	 * @param valueToHmac the value to HMAC
	 * @param hmacAlias the HMAC alias
	 * @param tokenizedRepresentation the tokenized representation label
	 */
	public CryptoShieldHmacHolder(String cryptoKeyId, String valueToHmac, String hmacAlias, String tokenizedRepresentation) {
		this.cryptoKeyId = cryptoKeyId;
		this.value = valueToHmac;
		this.hmacAlias = hmacAlias;
		this.tokenizedRepresentation = tokenizedRepresentation;
	}

	/**
	 * Returns the crypto key ID.
	 *
	 * @return the key ID
	 */
	public String getCryptoKeyId() {
		return cryptoKeyId;
	}

	/**
	 * Sets the crypto key ID.
	 *
	 * @param cryptoKeyId the key ID
	 */
	public void setCryptoKeyId(String cryptoKeyId) {
		this.cryptoKeyId = cryptoKeyId;
	}

	/**
	 * Returns the value or computed HMAC.
	 *
	 * @return the value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * Sets the value or computed HMAC.
	 *
	 * @param value the value
	 */
	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * Returns the HMAC alias.
	 *
	 * @return the alias
	 */
	public String getHmacAlias() {
		return hmacAlias;
	}

	/**
	 * Returns the tokenized representation label.
	 *
	 * @return the representation label
	 */
	public String getTokenizedRepresentation() {
		return tokenizedRepresentation;
	}

	/**
	 * Compares holders by key ID, value, alias, and representation.
	 *
	 * @param o the other object
	 * @return true when equal
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		CryptoShieldHmacHolder that = (CryptoShieldHmacHolder) o;
		return Objects.equals(cryptoKeyId, that.cryptoKeyId) && Objects.equals(value, that.value) && Objects.equals(hmacAlias, that.hmacAlias) && Objects.equals(tokenizedRepresentation, that.tokenizedRepresentation);
	}

	/**
	 * Returns the hash code for this holder.
	 *
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		return Objects.hash(cryptoKeyId, value, hmacAlias, tokenizedRepresentation);
	}
}
