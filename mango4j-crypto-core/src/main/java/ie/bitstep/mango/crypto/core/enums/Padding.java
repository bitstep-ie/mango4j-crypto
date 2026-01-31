package ie.bitstep.mango.crypto.core.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Padding {
	/**
	 * NONE - for testing negative scenarios
	 */
	NONE("NONE"),
	/**
	 * No padding - do not pad cipher text
	 */
	NO_PADDING("NoPadding"),
	/**
	 * PKCS1 - <a href="https://en.wikipedia.org/wiki/PKCS">Public Key Cryptography Standards 1 padding</a>
	 */
	PKCS1_PADDING("PKCS1Padding"),
	/**
	 * PKCS5 - <a href="https://en.wikipedia.org/wiki/PKCS">Public Key Cryptography Standards 5 padding</a>
	 */
	PKCS5_PADDING("PKCS5Padding");

	private final String padding; // NOSONAR

	Padding(String padding) {
		this.padding = padding;
	}

	/**
	 * Returns the padding value.
	 *
	 * @return the padding value
	 */
	@JsonValue
	public String getPadding() {
		return padding;
	}

	/**
	 * Parses padding from its string value.
	 *
	 * @param value the padding value
	 * @return the matching enum
	 */
	@JsonCreator
	public static Padding fromValue(String value) {
		for (Padding v : values()) {
			if (v.getPadding().equals(value)) {
				return v;
			}
		}

		throw new IllegalArgumentException("No enum constant with value: " + value);
	}
}
