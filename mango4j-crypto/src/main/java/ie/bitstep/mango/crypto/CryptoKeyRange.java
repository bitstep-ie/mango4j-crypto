package ie.bitstep.mango.crypto;

public class CryptoKeyRange {
	static final String INCREASING_FROM_OLDEST_DIRECTION = "increasing from oldest";
	static final String DECREASING_FROM_NEWEST_DIRECTION = "decreasing from newest";

	private static final CryptoKeyRange INCREASING_FROM_OLDEST = new CryptoKeyRange(INCREASING_FROM_OLDEST_DIRECTION);
	private static final CryptoKeyRange DECREASING_FROM_NEWEST = new CryptoKeyRange(DECREASING_FROM_NEWEST_DIRECTION);

	private final String direction;

	private CryptoKeyRange(String direction) {
		this.direction = direction;
	}

	public static CryptoKeyRange increasingFromOldest() {
		return INCREASING_FROM_OLDEST;
	}

	public static CryptoKeyRange decreasingFromNewest() {
		return DECREASING_FROM_NEWEST;
	}

	public String getDirection() {
		return direction;
	}
}
