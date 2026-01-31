package ie.bitstep.mango.crypto.core.utils;

import java.security.SecureRandom;

public class Generators {
	/**
	 * Prevents instantiation.
	 */
	private Generators() {
		// NOSONAR
	}

	/**
	 * Generates random bytes of the specified size.
	 *
	 * @param size number of bytes
	 * @return random byte array
	 */
	public static byte[] generateRandomBytes(int size) {
		final var secureRandomKeyBytes = new byte[size];
		final var secureRandom = new SecureRandom();
		secureRandom.nextBytes(secureRandomKeyBytes);

		return secureRandomKeyBytes;
	}

	/**
	 * Generates random bits of the specified size.
	 *
	 * @param size number of bits
	 * @return random byte array
	 */
	public static byte[] generateRandomBits(int size) {
		final var secureRandomKeyBytes = new byte[size / 8];
		final var secureRandom = new SecureRandom();
		secureRandom.nextBytes(secureRandomKeyBytes);

		return secureRandomKeyBytes;
	}

	/**
	 * Generates an initialization vector of the specified length.
	 *
	 * @param length IV length in bytes
	 * @return random IV bytes
	 */
	public static byte[] generateIV(final int length) {
		return generateRandomBytes(length);
	}
}
