package ie.bitstep.mango.crypto.core.factories;

import tools.jackson.databind.ObjectMapper;

public interface ObjectMapperFactory {
	/**
	 * Returns an ObjectMapper instance for crypto serialization.
	 *
	 * @return the ObjectMapper
	 */
	ObjectMapper objectMapper();
}
