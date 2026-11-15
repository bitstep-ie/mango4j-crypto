package ie.bitstep.mango.crypto.core.factories;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

public class ConfigurableObjectMapperFactory implements ObjectMapperFactory {
	public static final int ONE_KILOBYTE = 1024;
	private int maxStringLength = 20 * ONE_KILOBYTE;
	private ObjectMapper instance;

	/**
	 * Returns an ObjectMapper configured with stream read constraints.
	 *
	 * @return the configured ObjectMapper
	 */
	public synchronized ObjectMapper objectMapper() {
		if (instance == null) {
			StreamReadConstraints constraints = StreamReadConstraints.builder()
				.maxStringLength(maxStringLength)
				.build();

			JsonFactory jsonFactory = JsonFactory.builder()
				.streamReadConstraints(constraints)
				.build();

			instance = JsonMapper.builder(jsonFactory)
				.disable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
				.changeDefaultVisibility(visibility -> visibility.withFieldVisibility(JsonAutoDetect.Visibility.ANY))
				.build();
		}

		return instance;
	}

	/**
	 * Sets the maximum string length and resets the mapper.
	 *
	 * @param maxStringLength the maximum string length in characters
	 * @return this factory
	 */
	public synchronized ConfigurableObjectMapperFactory setMaxStringLength(int maxStringLength) {
		this.maxStringLength = maxStringLength;
		instance = null;
		return this;
	}
}
