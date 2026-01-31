package ie.bitstep.mango.crypto.core.factories;

import ie.bitstep.mango.crypto.core.factories.ConfigurableObjectMapperFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ConfigurableObjectMapperFactoryTest {

	@Test
	void objectMapper() {
		ConfigurableObjectMapperFactory configurableObjectMapperFactory = new ConfigurableObjectMapperFactory();

		assertNotNull(configurableObjectMapperFactory);
	}

	@Test
	void setMaxStringLength() {
		ConfigurableObjectMapperFactory configurableObjectMapperFactory = new ConfigurableObjectMapperFactory();

		assertNotNull(configurableObjectMapperFactory);
		assertNotNull(configurableObjectMapperFactory.setMaxStringLength(2000));
	}
}