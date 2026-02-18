package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;

import java.lang.reflect.Field;
import java.util.List;

/**
 * A couple of things are different for when we're rekeying HMACs for entities which use the {@link DoubleHmacFieldStrategy}
 * so this interface is used to allow the {@link RekeyDoubleHmacFieldStrategy} to help with that.
 */
interface DoubleHmacFieldStrategyDelegate {
	List<CryptoKey> getCurrentHmacKeys();

	void setFieldForOlderHmacKey(Object entity, List<HmacHolder> hmacHolders, List<Field> targetHmacFields);
}
