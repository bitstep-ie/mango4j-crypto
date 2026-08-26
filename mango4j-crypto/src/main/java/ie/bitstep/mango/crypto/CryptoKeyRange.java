package ie.bitstep.mango.crypto;

/**
 * Represents a range of crypto keys, either increasing from the oldest or decreasing from the newest.
 */
public class CryptoKeyRange {
	static final String INCREASING_FROM_OLDEST_DIRECTION = "increasing from oldest";
	static final String DECREASING_FROM_NEWEST_DIRECTION = "decreasing from newest";

	private static final CryptoKeyRange INCREASING_FROM_OLDEST = new CryptoKeyRange(INCREASING_FROM_OLDEST_DIRECTION);
	private static final CryptoKeyRange DECREASING_FROM_NEWEST = new CryptoKeyRange(DECREASING_FROM_NEWEST_DIRECTION);

	private final String direction;

	private CryptoKeyRange(String direction) {
		this.direction = direction;
	}

	/**
	 * Returns a CryptoKeyRange instance that iterates from the oldest to the newest crypto key.
	 *
	 * @return A CryptoKeyRange instance for increasing order from oldest.
	 */
	public static CryptoKeyRange increasingFromOldest() {
		return INCREASING_FROM_OLDEST;
	}

	/**
	 * Returns a CryptoKeyRange instance that iterates from the newest to the oldest crypto key.
	 *
	 * @return A CryptoKeyRange instance for decreasing order from newest.
	 */
	public static CryptoKeyRange decreasingFromNewest() {
		return DECREASING_FROM_NEWEST;
	}

	public String getDirection() {
		return direction;
	}
}
