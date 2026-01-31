package ie.bitstep.mango.crypto.tokenizers;

import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.util.ArrayList;
import java.util.List;

public class PanTokenizer implements HmacTokenizer {

	public static final String FIRST_6_REPRESENTATION_TEXT = "first6Digits";
	public static final String LAST_4_DIGITS_REPRESENTATION_TEXT = "last4Digits";
	public static final String NORMALIZED_PAN_REPRESENTATION_TEXT = "normalizedPan";

	private static final int PAN_MINIMUM_ALLOWED_NUMBER_OF_DIGITS = 13;
	private static final int PAN_PREFIX_LENGTH = 6;
	private static final int PAN_SUFFIX_LENGTH = 4;

	/**
	 * This method generates the following representations for a PAN:
	 * <ol>
	 *     <li>The PAN without spaces or dashes (if the original PAN contains either spaces or dashes)</li>
	 *     <li>The last 4 digits of the PAN (if the original PAN is over 12 digits in length)</li>
	 *     <li>The first 6 digits of the PAN (if the original PAN is over 12 digits in length)</li>
	 * </ol>
	 *
	 * <p>
	 * As per the {@link HmacTokenizer} documentation, none of the returned HMAC holders will contain the original PAN value, only the alternative
	 * representations of it.
	 * </p>
	 *
	 * @param hmacHolder Original (plaintext) {@link HmacHolder} built by the library for the associated field but
	 *                   without the hmacs calculated by the library yet.
	 * @return (original plaintext) {@link HmacHolder hmac holders} which contain alternative representations of a PAN which
	 * will have their hmacs calculated by the library alongside the original PAN value.
	 */
	@Override
	public List<HmacHolder> generateTokenizedValues(HmacHolder hmacHolder) {
		List<HmacHolder> tokenizedHmacHolders = new ArrayList<>();

		String originalPan = hmacHolder.getValue();
		String normalisedPan = normalise(originalPan);
		if (!originalPan.equals(normalisedPan)) {
			tokenizedHmacHolders.add(new HmacHolder(hmacHolder.getCryptoKey(), normalisedPan, hmacHolder.getHmacAlias(), NORMALIZED_PAN_REPRESENTATION_TEXT));
		}

		int normalisedPanLength = normalisedPan.length();
		if (normalisedPanLength >= PAN_MINIMUM_ALLOWED_NUMBER_OF_DIGITS) {
			tokenizedHmacHolders.add(new HmacHolder(hmacHolder.getCryptoKey(), normalisedPan.substring(0, PAN_PREFIX_LENGTH), hmacHolder.getHmacAlias(), FIRST_6_REPRESENTATION_TEXT));
			tokenizedHmacHolders.add(new HmacHolder(hmacHolder.getCryptoKey(), normalisedPan.substring(normalisedPanLength - PAN_SUFFIX_LENGTH), hmacHolder.getHmacAlias(), LAST_4_DIGITS_REPRESENTATION_TEXT));
		}
		return tokenizedHmacHolders;
	}

	/**
	 * Normalizes a PAN by removing spaces and dashes.
	 *
	 * @param value the input PAN
	 * @return the normalized PAN
	 */
	private String normalise(String value) {
		return value.replace(" ", "").replace("-", "");
	}
}
