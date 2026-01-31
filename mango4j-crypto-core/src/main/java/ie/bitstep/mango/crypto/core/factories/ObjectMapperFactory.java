package ie.bitstep.mango.crypto.core.factories;

import com.fasterxml.jackson.databind.ObjectMapper;

public interface ObjectMapperFactory {
	/**
	 * Returns an ObjectMapper instance for crypto serialization.
	 *
	 * @return the ObjectMapper
	 */
	ObjectMapper objectMapper();
}
