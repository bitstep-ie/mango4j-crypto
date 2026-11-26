package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import java.util.List;

public class RekeyListHmacFieldStrategy implements HmacStrategy, ListHmacFieldStrategyDelegate {

	private final ListHmacFieldStrategy wrappedListHmacFieldStrategy;
	private final List<CryptoKey> currentHmacCryptoKeys;

	public RekeyListHmacFieldStrategy(ListHmacFieldStrategy wrappedListHmacFieldStrategy, CryptoKey hmacCryptoKeyToKeyOnto) {
		this.wrappedListHmacFieldStrategy = wrappedListHmacFieldStrategy;
		this.currentHmacCryptoKeys = hmacCryptoKeyToKeyOnto == null ? List.of() : List.of(hmacCryptoKeyToKeyOnto);
	}

	public List<CryptoKey> getCurrentHmacKeys() {
		return currentHmacCryptoKeys;
	}

	public void hmac(Object entity) {
		wrappedListHmacFieldStrategy.hmac(entity, this);
	}
}
