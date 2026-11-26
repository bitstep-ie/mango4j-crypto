package ie.bitstep.mango.crypto.hmac;

import ie.bitstep.mango.crypto.HmacStrategyHelper;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.HmacHolder;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.single.TestAnnotatedEntityForSingleHmacFieldStrategy;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class RekeySingleHmacFieldStrategyTest {

	@Test
	void rekeyUsesExplicitTenantKeyWithoutConsultingProvider() {
		CryptoKey target = new CryptoKey();
		target.setId("target-tenant-key");
		CryptoKeyProvider provider = mock(CryptoKeyProvider.class);
		EncryptionService encryptionService = mock(EncryptionService.class);
		doAnswer(invocation -> {
			Collection<HmacHolder> holders = invocation.getArgument(0);
			holders.forEach(holder -> holder.setValue(holder.getCryptoKey().getId() + ":" + holder.getValue()));
			return null;
		}).when(encryptionService).hmac(any());
		SingleHmacFieldStrategy strategy = new SingleHmacFieldStrategy(
				TestAnnotatedEntityForSingleHmacFieldStrategy.class, new HmacStrategyHelper(encryptionService, provider));
		TestAnnotatedEntityForSingleHmacFieldStrategy entity = new TestAnnotatedEntityForSingleHmacFieldStrategy();
		entity.setPan("pan");
		entity.setUserName("name");

		new RekeySingleHmacFieldStrategy(strategy, target).hmac(entity);

		assertThat(entity.getPanHmac()).isEqualTo("target-tenant-key:pan");
		assertThat(entity.getUserNameHmac()).isEqualTo("target-tenant-key:name");
		assertThat(entity.getHmacKeyId()).isEqualTo("target-tenant-key");
		verifyNoInteractions(provider);
	}

	@Test
	void rekeyMarksTargetKeyWhenAllSourceValuesAreNull() {
		CryptoKey target = new CryptoKey();
		target.setId("target");
		CryptoKeyProvider provider = mock(CryptoKeyProvider.class);
		EncryptionService encryptionService = mock(EncryptionService.class);
		SingleHmacFieldStrategy strategy = new SingleHmacFieldStrategy(
				TestAnnotatedEntityForSingleHmacFieldStrategy.class, new HmacStrategyHelper(encryptionService, provider));
		TestAnnotatedEntityForSingleHmacFieldStrategy entity = new TestAnnotatedEntityForSingleHmacFieldStrategy();
		entity.setHmacKeyId("old");
		entity.setPanHmac("old-pan");
		entity.setUserNameHmac("old-name");

		new RekeySingleHmacFieldStrategy(strategy, target).hmac(entity);

		assertThat(entity.getHmacKeyId()).isEqualTo("target");
		assertThat(entity.getPanHmac()).isNull();
		assertThat(entity.getUserNameHmac()).isNull();
		verifyNoInteractions(provider, encryptionService);
	}
}
