package ie.bitstep.mango.crypto.hmac;

/**
 * Used to represent which approach to use for calculating the HMACs for field values in an entity
 * There are a few different ways in which an application could choose to persist the HMAC fields in its entities.
 * <p>
 * Currently there are 3 core supported {@link HmacStrategy HMAC Strategies}:
 * </p>
 * <p>
 * {@link SingleHmacFieldStrategy} - See associated javadocs for details.
 * </p>
 * <p>
 * {@link DoubleHmacFieldStrategy} - This is the default strategy the library uses. See associated javadocs for details.
 * </p>
 * <p>
 * {@link ListHmacFieldStrategy} - See associated javadocs for details.
 * </p>
 */
@FunctionalInterface
public interface HmacStrategy {
	/**
	 * Calculates HMACs for the supplied entity.
	 *
	 * @param entity the entity to process
	 */
	void hmac(Object entity);
}
