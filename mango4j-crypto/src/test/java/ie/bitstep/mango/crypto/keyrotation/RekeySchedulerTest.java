package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.AnnotatedEntityManager;
import ie.bitstep.mango.crypto.CipherGroup;
import ie.bitstep.mango.crypto.CryptoShield;
import ie.bitstep.mango.crypto.RekeyCryptoShield;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.hmac.SingleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.DoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.MockedConstruction;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_OFF;
import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_ON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RekeySchedulerTest {
	private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");

	@Test
	void futureKeyOnDoesNotStartRekeyOrCleanup() {
		CryptoKey old = key("old", NOW.minusSeconds(30), null, null);
		CryptoKey active = key("active", NOW.minusSeconds(20), null, null);
		CryptoKey future = key("future", NOW.minusSeconds(10), NOW.plusSeconds(1), KEY_ON);
		Harness harness = new Harness(List.of(old, active, future));

		harness.run();

		verifyNoInteractions(harness.service, harness.keyManager);
	}

	@Test
	void futureKeyIsExcludedFromTargetSelectionAndCleanup() {
		CryptoKey old = key("old", NOW.minusSeconds(30), null, null);
		CryptoKey active = key("active", NOW.minusSeconds(20), NOW.minusSeconds(1), KEY_ON);
		CryptoKey future = key("future", NOW.minusSeconds(10), NOW.plusSeconds(1), KEY_ON);
		Harness harness = new Harness(List.of(old, active, future));

		harness.run();

		verify(harness.service).findRecordsNotUsingCryptoKey(active);
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(future);
		verify(harness.keyManager).markKeyForDeletion(old);
		verify(harness.keyManager, never()).markKeyForDeletion(future);
	}

	@Test
	void keyIsEligibleAtItsStartTime() {
		CryptoKey old = key("old", NOW.minusSeconds(20), null, null);
		CryptoKey target = key("target", NOW.minusSeconds(10), NOW, KEY_ON);
		Harness harness = new Harness(List.of(old, target));

		harness.run();

		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.keyManager).markKeyForDeletion(old);
	}

	@Test
	void keyOffUsesActiveTargetInsteadOfFutureKey() {
		CryptoKey old = key("old", NOW.minusSeconds(30), null, KEY_OFF);
		CryptoKey active = key("active", NOW.minusSeconds(20), null, null);
		CryptoKey future = key("future", NOW.minusSeconds(10), NOW.plusSeconds(1), KEY_ON);
		Harness harness = new Harness(List.of(old, active, future));

		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> assertThat(context.arguments().get(2)).isEqualTo(active))) {
			harness.run();
			assertThat(construction.constructed()).hasSize(1);
		}

		verify(harness.service).findRecordsUsingCryptoKey(old);
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(future);
		verify(harness.keyManager).markKeyForDeletion(old);
		verify(harness.keyManager, never()).markKeyForDeletion(future);
	}

	@Test
	void keyOffIsDeferredIfTheOnlyOtherKeyIsNotYetActive() {
		CryptoKey old = key("old", NOW.minusSeconds(20), null, KEY_OFF);
		CryptoKey future = key("future", NOW.minusSeconds(10), NOW.plusSeconds(1), KEY_ON);
		Harness harness = new Harness(List.of(old, future));

		harness.run();

		verifyNoInteractions(harness.service, harness.keyManager);
	}

	@Test
	void noKeysOrNoRekeyModeDoNotStartJobs() {
		Harness empty = new Harness(List.of());
		empty.run();
		verifyNoInteractions(empty.service, empty.keyManager);

		Harness noMode = new Harness(List.of(key("one", NOW.minusSeconds(30), null, null),
				key("two", NOW.minusSeconds(20), null, null)));
		noMode.run();
		verifyNoInteractions(noMode.service, noMode.keyManager);
	}

	@Test
	void missingCreationDateSkipsTenant() {
		CryptoKey missingDate = key("missing", null, null, KEY_OFF);
		Harness harness = new Harness(List.of(missingDate, key("new", NOW.minusSeconds(20), null, null)));
		harness.run();
		verifyNoInteractions(harness.service, harness.keyManager);
	}

	@Test
	void tenantsAreProcessedUsingTheirOwnKeysIncludingNullTenant() {
		CryptoKey oldA = key("old-a", NOW.minusSeconds(30), null, null);
		CryptoKey targetA = key("target-a", NOW.minusSeconds(20), null, KEY_ON);
		CryptoKey oldB = key("old-b", NOW.minusSeconds(30), null, null);
		CryptoKey targetB = key("target-b", NOW.minusSeconds(20), null, KEY_ON);
		oldA.setTenantId(null);
		targetA.setTenantId(null);
		oldB.setTenantId("other-tenant");
		targetB.setTenantId("other-tenant");
		Harness harness = new Harness(List.of(oldA, targetB, targetA, oldB));

		harness.run();

		verify(harness.service).findRecordsNotUsingCryptoKey(targetA);
		verify(harness.service).findRecordsNotUsingCryptoKey(targetB);
		verify(harness.keyManager).markKeyForDeletion(oldA);
		verify(harness.keyManager).markKeyForDeletion(oldB);
		verify(harness.service, times(2)).notify(any());
	}

	@Test
	void invalidTenantDoesNotPreventOtherTenantFromRekeying() {
		CryptoKey invalid = key("invalid", null, null, KEY_ON);
		CryptoKey invalidOld = key("invalid-old", NOW.minusSeconds(30), null, null);
		CryptoKey goodOld = key("good-old", NOW.minusSeconds(30), null, null);
		CryptoKey goodTarget = key("good-target", NOW.minusSeconds(20), null, KEY_ON);
		goodOld.setTenantId("good");
		goodTarget.setTenantId("good");
		Harness harness = new Harness(List.of(invalid, invalidOld, goodOld, goodTarget));
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(goodTarget);
		verify(harness.keyManager).markKeyForDeletion(goodOld);
		verify(harness.keyManager, never()).markKeyForDeletion(invalidOld);
	}

	@Test
	void hmacValidationRejectsInvalidModesAndInsufficientKeys() {
		CryptoKey olderOn = key("older-on", NOW.minusSeconds(30), null, KEY_ON);
		CryptoKey newer = key("newer", NOW.minusSeconds(20), null, null);
		Harness older = new Harness(List.of(olderOn, newer));
		older.run();
		verify(older.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(older.keyManager);

		CryptoKey newerOff = key("newer-off", NOW.minusSeconds(20), null, KEY_OFF);
		Harness latestOff = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), newerOff));
		latestOff.run();
		verify(latestOff.service, never()).findRecordsUsingCryptoKey(any());
		verifyNoInteractions(latestOff.keyManager);

		CryptoKey only = key("only", NOW.minusSeconds(20), null, KEY_ON);
		CryptoKey encryption = encryptionKey("encryption", NOW.minusSeconds(30), null, "");
		Harness oneHmacKey = new Harness(List.of(only, encryption));
		oneHmacKey.run();
		verify(oneHmacKey.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(oneHmacKey.keyManager);
	}

	@Test
	void cachePeriodDefersHmacRekeyAndCleanup() {
		CryptoKey old = key("old", NOW.minusSeconds(60), null, null);
		CryptoKey target = key("new", NOW.minusSeconds(10), null, KEY_ON);
		Harness harness = new Harness(List.of(old, target));
		when(harness.config.getCryptoKeyCacheDuration()).thenReturn(Duration.ofSeconds(20));
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void singleKeyOnRekeysBatchesAndReportsProgress() {
		CryptoKey old = key("old", NOW.minusSeconds(30), null, null);
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(old, target));
		TestEntity first = new TestEntity();
		TestEntity second = new TestEntity();
		doReturn(List.of(first, second), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);

		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> {
					assertThat(context.arguments().get(1)).isNull();
					assertThat(context.arguments().get(2)).isEqualTo(target);
				})) {
			harness.run();
			RekeyCryptoShield shield = construction.constructed().get(0);
			org.mockito.InOrder order = inOrder(shield, harness.service);
			order.verify(shield).decrypt(first);
			order.verify(shield).encrypt(first);
			order.verify(shield).decrypt(second);
			order.verify(shield).encrypt(second);
			order.verify(harness.service).save(List.of(first, second));
		}

		verify(harness.service, times(2)).findRecordsNotUsingCryptoKey(target);
		ArgumentCaptor<RekeyEvent> event = ArgumentCaptor.forClass(RekeyEvent.class);
		verify(harness.service).notify(event.capture());
		assertThat(event.getValue().getType()).isEqualTo(RekeyEvent.Type.REKEY_FINISHED);
		assertThat(event.getValue().getCryptoKeysThatTriggeredTheRekey()).containsExactly(target);
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsProcessed()).isEqualTo(2);
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsFailed()).isZero();
		assertThat(event.getValue().getProgressTracker().getNumberOfBatchesProcessed()).isEqualTo(2);
	}

	@Test
	void nullBatchEndsRekeyWithoutSaving() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		doReturn(null).when(harness.service).findRecordsNotUsingCryptoKey(target);
		harness.run();
		verify(harness.service, never()).save(any());
		verify(harness.service).notify(any());
	}

	@Test
	void doubleStrategyKeyOffQueriesLatestKey() {
		CryptoKey old = key("old", NOW.minusSeconds(30), null, KEY_OFF);
		CryptoKey target = key("target", NOW.minusSeconds(20), null, null);
		Harness harness = new Harness(List.of(old, target));
		when(harness.manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.of(mock(DoubleHmacFieldStrategy.class)));
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> assertThat(context.arguments().get(2)).isEqualTo(target))) {
			harness.run();
			assertThat(construction.constructed()).hasSize(1);
		}
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.service, never()).findRecordsUsingCryptoKey(old);
	}

	@Test
	void listStrategyKeyOnQueriesTarget() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		when(harness.manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.of(mock(ListHmacFieldStrategy.class)));
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
	}

	@Test
	void doubleStrategyKeyOnQueriesTarget() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		when(harness.manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.of(mock(DoubleHmacFieldStrategy.class)));
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
	}

	@Test
	void listStrategyKeyOffUsesOldestNonKeyOffTarget() {
		CryptoKey old = key("old", NOW.minusSeconds(40), null, KEY_OFF);
		CryptoKey middle = key("middle", NOW.minusSeconds(30), null, null);
		CryptoKey latest = key("latest", NOW.minusSeconds(20), null, null);
		Harness harness = new Harness(List.of(latest, old, middle));
		when(harness.manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.of(mock(ListHmacFieldStrategy.class)));
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> assertThat(context.arguments().get(2)).isEqualTo(middle))) {
			harness.run();
			assertThat(construction.constructed()).hasSize(1);
		}
		verify(harness.service).findRecordsNotUsingCryptoKey(middle);
		verify(harness.keyManager).markKeyForDeletion(old);
	}

	@Test
	void entityWithoutHmacStrategyDoesNotStartHmacTask() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		when(harness.manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.empty());
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verify(harness.service, never()).notify(any());
	}

	@Test
	void keyOffOnMiddleHmacKeyDoesNotStartTask() {
		CryptoKey old = key("old", NOW.minusSeconds(40), null, null);
		CryptoKey middle = key("middle", NOW.minusSeconds(30), null, KEY_OFF);
		CryptoKey latest = key("latest", NOW.minusSeconds(20), null, null);
		Harness harness = new Harness(List.of(old, middle, latest));
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verify(harness.service, never()).findRecordsUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void encryptionKeyOnUsesMatchingSelectorAndCleansUpOnlyUnusedKey() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "selector");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, "selector");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("selector");
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> {
					assertThat(context.arguments().get(1)).isEqualTo(target);
					assertThat(context.arguments().get(2)).isNull();
				})) {
			harness.run();
			assertThat(construction.constructed()).hasSize(1);
		}
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.service).findRecordsUsingCryptoKey(old);
		verify(harness.keyManager).markKeyForDeletion(old);
	}

	@Test
	void encryptionKeyOffQueriesOldKeyAndRetainsItWhileInUse() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), KEY_OFF, "selector");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), null, "selector");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("selector");
		doReturn(List.of(), List.of(new TestEntity())).when(harness.service).findRecordsUsingCryptoKey(old);
		harness.run();
		verify(harness.service, times(2)).findRecordsUsingCryptoKey(old);
		verify(harness.keyManager, never()).markKeyForDeletion(old);
	}

	@Test
	void encryptionRekeySkipsNonMatchingSelectorAndUnusedSelectorCleanup() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "other");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, "other");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("selector");
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void encryptionRekeySkipsEntityWithoutEncryptedFields() {
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, "");
		Harness harness = new Harness(List.of(encryptionKey("old", NOW.minusSeconds(30), null, ""), target));
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void encryptionKeyOffProcessesEachKeyForMatchingSelector() {
		CryptoKey oldest = encryptionKey("oldest", NOW.minusSeconds(40), KEY_OFF, "");
		CryptoKey older = encryptionKey("older", NOW.minusSeconds(30), KEY_OFF, "");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), null, "");
		Harness harness = new Harness(List.of(older, target, oldest));
		harness.cipherGroups("");
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> assertThat(context.arguments().get(1)).isEqualTo(target))) {
			harness.run();
			assertThat(construction.constructed()).hasSize(2);
		}
		verify(harness.service, times(2)).findRecordsUsingCryptoKey(oldest);
		verify(harness.service, times(2)).findRecordsUsingCryptoKey(older);
		verify(harness.keyManager).markKeyForDeletion(oldest);
		verify(harness.keyManager).markKeyForDeletion(older);
		ArgumentCaptor<RekeyEvent> event = ArgumentCaptor.forClass(RekeyEvent.class);
		verify(harness.service).notify(event.capture());
		assertThat(event.getValue().getCryptoKeysThatTriggeredTheRekey()).containsExactlyInAnyOrder(oldest, older);
	}

	@Test
	void nullEncryptionSelectorMatchesDefaultCipherGroup() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, null);
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, null);
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("");
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.keyManager).markKeyForDeletion(old);
	}

	@Test
	void encryptionInvalidLatestKeyOffAndSingleKeyGroupAreSkipped() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "");
		CryptoKey latest = encryptionKey("latest", NOW.minusSeconds(20), KEY_OFF, "");
		Harness invalid = new Harness(List.of(old, latest));
		invalid.cipherGroups("");
		invalid.run();
		verify(invalid.service, never()).findRecordsUsingCryptoKey(any());
		verifyNoInteractions(invalid.keyManager);

		CryptoKey only = encryptionKey("only", NOW.minusSeconds(20), KEY_ON, "one");
		CryptoKey unrelated = encryptionKey("other", NOW.minusSeconds(30), null, "two");
		Harness single = new Harness(List.of(only, unrelated));
		single.cipherGroups("one");
		single.run();
		verify(single.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(single.keyManager);
	}

	@Test
	void encryptionCleanupRetainsKeyIfUsageCheckFails() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, "");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("");
		when(harness.service.findRecordsUsingCryptoKey(old)).thenThrow(new IllegalStateException());
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.keyManager, never()).markKeyForDeletion(old);
	}

	@Test
	void encryptionCleanupRetainsKeyIfUsageCheckReturnsNull() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(20), KEY_ON, "");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("");
		doReturn(null).when(harness.service).findRecordsUsingCryptoKey(old);
		harness.run();
		verify(harness.service).findRecordsNotUsingCryptoKey(target);
		verify(harness.keyManager, never()).markKeyForDeletion(old);
	}

	@Test
	void encryptionCachePeriodDefersRekeyAndCleanup() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "");
		CryptoKey target = encryptionKey("target", NOW.minusSeconds(10), KEY_ON, "");
		Harness harness = new Harness(List.of(old, target));
		harness.cipherGroups("");
		when(harness.config.getCryptoKeyCacheDuration()).thenReturn(Duration.ofSeconds(20));
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void futureEncryptionKeyIsIgnoredUntilItsStartTime() {
		CryptoKey old = encryptionKey("old", NOW.minusSeconds(30), null, "");
		CryptoKey future = encryptionKey("future", NOW.minusSeconds(20), KEY_ON, "");
		future.setKeyStartTime(NOW.plusSeconds(1));
		Harness harness = new Harness(List.of(old, future));
		harness.cipherGroups("");
		harness.run();
		verify(harness.service, never()).findRecordsNotUsingCryptoKey(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void decryptFailureIsCountedAndOtherRecordsAreProcessed() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		TestEntity failed = new TestEntity();
		TestEntity successful = new TestEntity();
		doReturn(List.of(failed, successful), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		when(harness.config.getMaximumToleratedFailuresPerExecution()).thenReturn(-1);
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> doThrow(new IllegalStateException()).when(mock).decrypt(failed))) {
			harness.run();
			RekeyCryptoShield shield = construction.constructed().get(0);
			verify(shield, never()).encrypt(failed);
			verify(shield).encrypt(successful);
		}
		ArgumentCaptor<RekeyEvent> event = ArgumentCaptor.forClass(RekeyEvent.class);
		verify(harness.service).notify(event.capture());
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsProcessed()).isEqualTo(2);
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsFailed()).isEqualTo(1);
	}

	@Test
	void encryptFailureIsCountedAndOtherRecordsAreProcessed() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		TestEntity failed = new TestEntity();
		TestEntity successful = new TestEntity();
		doReturn(List.of(failed, successful), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		when(harness.config.getMaximumToleratedFailuresPerExecution()).thenReturn(-1);
		try (MockedConstruction<RekeyCryptoShield> construction = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> doThrow(new IllegalStateException()).when(mock).encrypt(failed))) {
			harness.run();
			verify(construction.constructed().get(0)).encrypt(successful);
		}
		ArgumentCaptor<RekeyEvent> event = ArgumentCaptor.forClass(RekeyEvent.class);
		verify(harness.service).notify(event.capture());
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsFailed()).isEqualTo(1);
	}

	@Test
	void positiveBatchIntervalProcessesNextBatch() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		doReturn(List.of(new TestEntity()), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		when(harness.config.getBatchInterval()).thenReturn(Duration.ofMillis(1));
		try (MockedConstruction<RekeyCryptoShield> ignored = mockConstruction(RekeyCryptoShield.class)) {
			harness.run();
		}
		verify(harness.service, times(2)).findRecordsNotUsingCryptoKey(target);
		verify(harness.service).notify(any());
	}

	@Test
	void interruptedBatchWaitStopsRekeyAndPreservesInterrupt() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		doReturn(List.of(new TestEntity()), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		when(harness.config.getBatchInterval()).thenReturn(Duration.ofMillis(1));
		try (MockedConstruction<RekeyCryptoShield> ignored = mockConstruction(RekeyCryptoShield.class)) {
			Thread.currentThread().interrupt();
			harness.run();
			assertThat(Thread.currentThread().isInterrupted()).isTrue();
		} finally {
			Thread.interrupted();
		}
		verify(harness.service, times(1)).findRecordsNotUsingCryptoKey(target);
		verify(harness.service, never()).notify(any());
		verifyNoInteractions(harness.keyManager);
	}

	@Test
	void deletionManagerFailureDoesNotPreventLaterKeyCleanup() {
		CryptoKey oldest = key("oldest", NOW.minusSeconds(40), null, null);
		CryptoKey older = key("older", NOW.minusSeconds(30), null, null);
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(oldest, older, target));
		doThrow(new IllegalStateException()).when(harness.keyManager).markKeyForDeletion(older);
		harness.run();
		verify(harness.keyManager).markKeyForDeletion(older);
		verify(harness.keyManager).markKeyForDeletion(oldest);
	}

	@Test
	void saveFailureIsCountedInProgress() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		TestEntity entity = new TestEntity();
		doReturn(List.of(entity), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		doThrow(new IllegalStateException()).when(harness.service).save(any());
		when(harness.config.getMaximumToleratedFailuresPerExecution()).thenReturn(-1);
		try (MockedConstruction<RekeyCryptoShield> ignored = mockConstruction(RekeyCryptoShield.class)) {
			harness.run();
		}
		ArgumentCaptor<RekeyEvent> event = ArgumentCaptor.forClass(RekeyEvent.class);
		verify(harness.service).notify(event.capture());
		assertThat(event.getValue().getProgressTracker().getNumberOfRecordsFailed()).isEqualTo(1);
	}

	@Test
	void failureLimitStopsProcessingWithoutCompletionNotification() {
		CryptoKey target = key("target", NOW.minusSeconds(20), null, KEY_ON);
		Harness harness = new Harness(List.of(key("old", NOW.minusSeconds(30), null, null), target));
		TestEntity entity = new TestEntity();
		doReturn(List.of(entity), List.of()).when(harness.service).findRecordsNotUsingCryptoKey(target);
		when(harness.config.getMaximumToleratedFailuresPerExecution()).thenReturn(0);
		try (MockedConstruction<RekeyCryptoShield> ignored = mockConstruction(RekeyCryptoShield.class,
				(mock, context) -> doThrow(new IllegalStateException()).when(mock).decrypt(entity))) {
			harness.run();
		}
		verify(harness.service, never()).notify(any());
		verifyNoInteractions(harness.keyManager);
	}

	private static CryptoKey key(String id, Instant created, Instant start, CryptoKey.RekeyMode mode) {
		CryptoKey key = new CryptoKey();
		key.setId(id);
		key.setTenantId("tenant");
		key.setUsage(CryptoKeyUsage.HMAC);
		key.setCreatedDate(created);
		key.setKeyStartTime(start);
		key.setRekeyMode(mode);
		return key;
	}

	private static CryptoKey encryptionKey(String id, Instant created, CryptoKey.RekeyMode mode, String selector) {
		CryptoKey key = key(id, created, null, mode);
		key.setUsage(CryptoKeyUsage.ENCRYPTION);
		key.setKeySelector(selector);
		return key;
	}

	private static class Harness {
		private final RekeyService<?> service = mock(RekeyService.class);
		private final RekeyCryptoKeyManager keyManager = mock(RekeyCryptoKeyManager.class);
		private final AnnotatedEntityManager manager = mock(AnnotatedEntityManager.class);
		private final RekeySchedulerConfig config = mock(RekeySchedulerConfig.class);
		private final Runnable scheduledTask;

		private Harness(List<CryptoKey> keys) {
			ScheduledExecutorService executor = mock(ScheduledExecutorService.class);
			when(config.getClock()).thenReturn(Clock.fixed(NOW, ZoneOffset.UTC));
			CryptoShield shield = mock(CryptoShield.class);
			when(config.getCryptoShield()).thenReturn(shield);
			when(config.getRekeyServices()).thenReturn(List.of(service));
			when(config.getRekeyCryptoKeyManager()).thenReturn(keyManager);
			when(config.getCryptoKeyCacheDuration()).thenReturn(Duration.ZERO);
			when(config.getBatchInterval()).thenReturn(Duration.ZERO);
			when(config.getRekeyCheckInterval()).thenReturn(1);
			when(config.getRekeyTimeUnits()).thenReturn(TimeUnit.DAYS);
			CryptoKeyProvider provider = mock(CryptoKeyProvider.class);
			when(shield.getCryptoKeyProvider()).thenReturn(provider);
			when(shield.getAnnotatedEntityManager()).thenReturn(manager);
			when(provider.getAllCryptoKeys()).thenReturn(keys);
			when(service.getEntityType()).thenAnswer(invocation -> TestEntity.class);
			when(manager.getHmacStrategy(TestEntity.class)).thenReturn(Optional.of(mock(SingleHmacFieldStrategy.class)));
			ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
			try (MockedStatic<Executors> executors = mockStatic(Executors.class)) {
				executors.when(() -> Executors.newScheduledThreadPool(1)).thenReturn(executor);
				new RekeyScheduler(config);
				verify(executor).scheduleAtFixedRate(task.capture(), eq(0L), eq(1L), eq(TimeUnit.DAYS));
			}
			scheduledTask = task.getValue();
		}

		private void run() {
			scheduledTask.run();
		}

		private void cipherGroups(String selector) {
			when(manager.getCipherGroups(TestEntity.class)).thenReturn(List.of(new CipherGroup("group", selector, List.of(), null, null)));
		}
	}

	private static class TestEntity {
	}
}
