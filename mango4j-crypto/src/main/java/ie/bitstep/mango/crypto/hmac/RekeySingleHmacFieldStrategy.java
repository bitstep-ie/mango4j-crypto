package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.Objects;

public class RekeySingleHmacFieldStrategy implements HmacStrategy {

	private final SingleHmacFieldStrategy wrappedSingleHmacFieldStrategy;
	private final SingleHmacFieldStrategyDelegate delegate;

	public RekeySingleHmacFieldStrategy(SingleHmacFieldStrategy wrappedSingleHmacFieldStrategy, CryptoKey currentHmacCryptoKey) {
		this.wrappedSingleHmacFieldStrategy = Objects.requireNonNull(wrappedSingleHmacFieldStrategy);
		CryptoKey targetKey = Objects.requireNonNull(currentHmacCryptoKey);
		this.delegate = () -> targetKey;
	}

	@Override
	public void hmac(Object entity) {
		wrappedSingleHmacFieldStrategy.hmac(entity, delegate);
	}
}
