package ie.bitstep.mango.crypto.tokenizers;

import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.util.List;

/**
 * Applications can supply their own {@link HmacTokenizer} implementations which they can then assign to fields with the
 * {@link Hmac @Hmac} annotation.
 * <p>
 * i.e. {@literal @Hmac(hmacTokenizers = {PanTokenizer.class})}
 * </p>
 * <b>Note: All implementations of this interface must have a default no-args constructor</b>
 */
@FunctionalInterface
public interface HmacTokenizer {
	/**
	 * This method is called before the library calculates the HMAC for lookup fields.
	 *
	 * @param hmacHolder The original (non-hmac [plaintext]) {@link HmacHolder} that the library builds for this field value.
	 * @return A list of {@link HmacHolder hmacHolders} which will contain all the tokenized values
	 * that the implementation generates for the original field value. This list must <b><u>not</u></b> contain the original
	 * hmacHolder parameter passed in, only the extra generated {@link HmacHolder hmacHolders} for the tokenized values.
	 */
	List<HmacHolder> generateTokenizedValues(HmacHolder hmacHolder);
}
