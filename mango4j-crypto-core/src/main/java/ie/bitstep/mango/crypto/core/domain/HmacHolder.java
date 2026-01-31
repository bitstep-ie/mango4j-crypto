package ie.bitstep.mango.crypto.core.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;

import java.util.Objects;

/**
 * Please read the official documentation for this library to understand why we use this class.
 */
public final class HmacHolder {

	/**
	 * {@link CryptoKey} to be used for calculating the HMAC.
	 */
	private CryptoKey cryptoKey;

	/**
	 * Data to calculate the HMAC for.
	 * <br>
	 * {@link EncryptionService#hmac(java.util.Collection)
	 * EncryptionService#hmac(Collection<HmacHolder>)} will overwrite this field with the result of the
	 * HMAC operation.
	 */
	private String value;

	/**
	 * Optional value which can be set by applications. This is necessary to facilitate HMAC service implementations which
	 * can call an external cryptographic providers batch HMAC call. i.e. Some cryptographic providers may offer operations which accept
	 * multiple values to HMAC in the request so applications can calculate the HMACs for multiple values with a single call.
	 * However, these
	 * types of operations need each value to be accompanied by an associated alias for the value so that applications
	 * can tell which HMAC values in the response correspond to which input values. It is encouraged that applications
	 * collect all values from their data model that they need to HMAC into a single list and call
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection<HmacHolder>)}
	 * only once for better performance. Rather than calling
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection<HmacHolder>)}
	 * to HMAC the PAN list, then calling it again to HMAC the username list, etc. (remember each field generates a list of
	 * {@link HmacHolder HMAC holders} to accommodate key rotation).
	 * <p>
	 * Bundle them all into one list setting this field
	 * on each one to an appropriate value and make a single call. If this field isn't set then an application must call
	 * {@link EncryptionService#hmac(java.util.Collection) EncryptionService.hmac(Collection<HmacHolder>)}
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
	 * In this case each {@link HmacHolder} needs to document which HMAC it actually corresponds to (since the hmacAlias
	 * field would have the same value, 'pan' or whatever and would no longer not be enough to tell them apart) so it can
	 * use this field to do that. i.e. for the above example the PanTokenizer would set this field to 'last4Digits' for
	 * the HMAC which was generated for the last 4 digits of the pan and set this field to 'withoutDashes' for the HMAC
	 * which was generated for the PAN with the dashes removed. Having this field set to helpful values when using
	 * tokenizers might help for application search functions. If an application doesn't use tokenizers on any HMAC
	 * fields then this field can be left blank as it would serve no purpose.
	 */
	private final String tokenizedRepresentation;

	/**
	 * Creates a holder with a key and value.
	 *
	 * @param cryptoKey the crypto key
	 * @param valueToHmac the value to HMAC
	 */
	public HmacHolder(CryptoKey cryptoKey, String valueToHmac) {
		this(cryptoKey, valueToHmac, null);
	}

	/**
	 * Creates a holder with a key, value, and alias.
	 *
	 * @param cryptoKey the crypto key
	 * @param valueToHmac the value to HMAC
	 * @param name the alias for the value
	 */
	public HmacHolder(CryptoKey cryptoKey, String valueToHmac, String name) {
		this(cryptoKey, valueToHmac, name, null);
	}

	/**
	 * Creates a holder with key, value, alias, and tokenized representation.
	 *
	 * @param cryptoKey the crypto key
	 * @param valueToHmac the value to HMAC
	 * @param hmacAlias the alias for the value
	 * @param tokenizedRepresentation the tokenized representation label
	 */
	public HmacHolder(CryptoKey cryptoKey, String valueToHmac, String hmacAlias, String tokenizedRepresentation) {
		this.cryptoKey = cryptoKey;
		this.value = valueToHmac;
		this.hmacAlias = hmacAlias;
		this.tokenizedRepresentation = tokenizedRepresentation;
	}

	/**
	 * Returns the crypto key used for this holder.
	 *
	 * @return the crypto key
	 */
	@JsonProperty("cryptoKey")
	public CryptoKey getCryptoKey() {
		return cryptoKey;
	}

	/**
	 * Sets the crypto key for this holder.
	 *
	 * @param cryptoKey the crypto key
	 */
	public void setCryptoKey(CryptoKey cryptoKey) {
		this.cryptoKey = cryptoKey;
	}

	/**
	 * Returns the value to HMAC (or the computed HMAC after processing).
	 *
	 * @return the value
	 */
	@JsonProperty("value")
	public String getValue() {
		return value;
	}

	/**
	 * Sets the value to HMAC (or stores a computed HMAC).
	 *
	 * @param value the value to set
	 */
	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * Returns the HMAC alias, if any.
	 *
	 * @return the alias
	 */
	@JsonProperty("hmacAlias")
	public String getHmacAlias() {
		return hmacAlias;
	}

	/**
	 * Returns the tokenized representation label, if any.
	 *
	 * @return the tokenized representation label
	 */
	@JsonProperty("tokenizedRepresentation")
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
		HmacHolder that = (HmacHolder) o;
		return Objects.equals(cryptoKey.getId(), that.cryptoKey.getId()) && Objects.equals(value, that.value) && Objects.equals(hmacAlias, that.hmacAlias) && Objects.equals(tokenizedRepresentation, that.tokenizedRepresentation);
	}

	/**
	 * Returns the hash code for this holder.
	 *
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		return Objects.hash(cryptoKey, value, hmacAlias, tokenizedRepresentation);
	}
}
