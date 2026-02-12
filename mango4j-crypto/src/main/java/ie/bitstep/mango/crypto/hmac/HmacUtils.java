package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.exceptions.NoHmacKeysFoundException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

import static java.util.Comparator.nullsLast;
import static java.util.Comparator.reverseOrder;
import static java.util.stream.Collectors.toCollection;

class HmacUtils {

	static List<CryptoKey> hmacKeysInCreationDateDescendingOrder(List<CryptoKey> currentHmacKeys) {
		if (currentHmacKeys == null || currentHmacKeys.isEmpty()) {
			throw new NoHmacKeysFoundException();
		}

		// existing list could be unmodifiable so create a new list to sort
		return currentHmacKeys.stream()
				.filter(Objects::nonNull)
				.sorted(Comparator.comparing(CryptoKey::getCreatedDate, nullsLast(reverseOrder())))
				.collect(toCollection(ArrayList::new));
	}
}