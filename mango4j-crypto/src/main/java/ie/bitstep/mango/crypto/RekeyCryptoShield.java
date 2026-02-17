package ie.bitstep.mango.crypto;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.RekeyListHmacFieldStrategy;

import java.util.List;
import java.util.Optional;

public class RekeyCryptoShield {
	private final CryptoShield cryptoShield;
	private final CryptoShieldDelegate rekeyCryptoShieldDelegate;

	public RekeyCryptoShield(CryptoShield cryptoShield,
							 CryptoKey currentEncryptionKey,
							 List<CryptoKey> currentHmacKeys) {
		this.cryptoShield = cryptoShield;
		this.rekeyCryptoShieldDelegate = new CryptoShieldDelegate() {

			@Override
			public CryptoKey getCurrentEncryptionKey() {
				return currentEncryptionKey;
			}

			@Override
			public Optional<HmacStrategy> getHmacStrategy(Object entity) {
				Optional<HmacStrategy> hmacStrategy = cryptoShield.getAnnotatedEntityManager().getHmacStrategy(entity.getClass());
				if (hmacStrategy.isPresent() &&
						!currentHmacKeys.isEmpty() &&
						hmacStrategy.get().getClass().isAssignableFrom(ListHmacFieldStrategy.class)) {
					RekeyListHmacFieldStrategy rekeyListHmacFieldStrategy = new RekeyListHmacFieldStrategy((ListHmacFieldStrategy) hmacStrategy.get(), currentHmacKeys);
					hmacStrategy = Optional.of(rekeyListHmacFieldStrategy);
				} else if (currentHmacKeys.isEmpty()) {
					return Optional.empty();
				}
				return hmacStrategy;
			}
		};
	}

	public void decrypt(Object entity) {
		cryptoShield.decrypt(entity);
	}

	public void encrypt(Object entity) {
		cryptoShield.encrypt(entity, rekeyCryptoShieldDelegate);
	}
}