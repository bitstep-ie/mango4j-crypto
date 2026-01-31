package ie.bitstep.mango.crypto.exceptions;

import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.tokenizers.HmacTokenizer;

public class HmacTokenizerInstantiationException extends NonTransientCryptoException {

	/**
	 * Creates an exception when a tokenizer cannot be instantiated.
	 *
	 * @param hmacTokenizerClass the tokenizer class
	 */
	public HmacTokenizerInstantiationException(Class<? extends HmacTokenizer> hmacTokenizerClass) {
		super(String.format("Could not create an instance of %s type %2$s. Please make sure that %2$s has a default no-args constructor declared",
			HmacTokenizer.class.getSimpleName(), hmacTokenizerClass.getSimpleName()));
	}
}
