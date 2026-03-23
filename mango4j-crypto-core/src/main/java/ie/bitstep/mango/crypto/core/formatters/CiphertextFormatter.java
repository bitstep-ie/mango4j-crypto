package ie.bitstep.mango.crypto.core.formatters;

import ie.bitstep.mango.crypto.core.domain.CiphertextContainer;

public interface CiphertextFormatter {
	CiphertextContainer parse(String data);

	String format(CiphertextContainer ciphertextContainer);
}
