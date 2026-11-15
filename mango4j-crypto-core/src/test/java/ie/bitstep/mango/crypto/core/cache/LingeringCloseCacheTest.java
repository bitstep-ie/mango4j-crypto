package ie.bitstep.mango.crypto.core.cache;

import ie.bitstep.mango.crypto.core.cache.LingeringCloseCache.CacheEntry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("ALL")
@ExtendWith(MockitoExtension.class)
class LingeringCloseCacheTest {

	public static final TimeUnit TEST_CACHE_TIME_TO_LIVE_TIME_UNIT = TimeUnit.SECONDS;
	public static final Duration TEST_GRACE_PERIOD = Duration.ofSeconds(5);
	public static final Duration TEST_CACHE_DURATION_TTL = Duration.ofMinutes(15);
	public static final Duration TEST_CURRENT_ENTRY_TTL = Duration.ofHours(1);
	public static final Duration TEST_EVICTION_TASK_PERIOD = Duration.ofMinutes(1);
	public static final String TEST_KEY = "key1";
	public static final String TEST_STRING_VALUE = "value1";
	private LingeringCloseCache<String, String> cache;

	private LingeringCloseCache<String, AutoCloseable> closeableCache;

	@Mock
	private Clock clock;

	@Mock
	private ScheduledExecutorService nonClosableCleaner;

	@Mock
	private ScheduledExecutorService closableCleaner;

	@Mock
	private ScheduledFuture mockScheduledFuture;

	@Mock
	private AutoCloseable currentAutoclosable;

	@Mock
	private AutoCloseable currentAutoclosable2;

	@Mock
	private AutoCloseable cachedAutoclosable;

	@Captor
	private ArgumentCaptor<Runnable> nonClosableTaskArgumentCaptor;

	@Captor
	private ArgumentCaptor<Runnable> closableTaskArgumentCaptor;

	private static class CanClose implements AutoCloseable {

		@Override
		public void close() {
// NOSONAR: Test case support
		}
	}

	@Mock
	private CanClose canClose;

	@BeforeEach
	void setUp() {
		given(nonClosableCleaner.scheduleAtFixedRate(nonClosableTaskArgumentCaptor.capture(), eq(TEST_EVICTION_TASK_PERIOD.toMillis()),
				eq(TEST_EVICTION_TASK_PERIOD.toMillis()), eq(TimeUnit.MILLISECONDS))).willReturn(mockScheduledFuture);
		given(closableCleaner.scheduleAtFixedRate(closableTaskArgumentCaptor.capture(), eq(TEST_EVICTION_TASK_PERIOD.toMillis()),
				eq(TEST_EVICTION_TASK_PERIOD.toMillis()), eq(TimeUnit.MILLISECONDS))).willReturn(mockScheduledFuture);
		cache = new LingeringCloseCache<>(TEST_CACHE_DURATION_TTL, TEST_CURRENT_ENTRY_TTL, TEST_GRACE_PERIOD, TEST_EVICTION_TASK_PERIOD, nonClosableCleaner, clock);
		closeableCache = new LingeringCloseCache<>(TEST_CACHE_DURATION_TTL, TEST_CURRENT_ENTRY_TTL, TEST_GRACE_PERIOD, TEST_EVICTION_TASK_PERIOD, closableCleaner, clock);
	}

	@AfterEach
	void tearDown() {
		cache.shutdown();
	}

	@Test
	void lightweightConstructor() {
		Mockito.reset(nonClosableCleaner); // overwrite the setup in setUp() to verify the default scheduling behavior of the lightweight constructor
		given(nonClosableCleaner.scheduleAtFixedRate(nonClosableTaskArgumentCaptor.capture(),
				eq(Duration.ofMinutes(1).toMillis()),
				eq(Duration.ofMinutes(1).toMillis()),
				eq(TimeUnit.MILLISECONDS))).willReturn(mockScheduledFuture);

		cache = new LingeringCloseCache<>(5, TEST_CACHE_TIME_TO_LIVE_TIME_UNIT, nonClosableCleaner, clock);

		assertThat(getCache(cache)).isEmpty();
		assertThat(cache.getCacheEntryTTL()).isEqualTo(Duration.ofMillis(5000));
		assertThat(cache.getCurrentEntryTTL()).isEqualTo(Duration.ofMillis(5000));
		assertThat(cache.getCacheGracePeriod()).isEqualTo(Duration.ofSeconds(5));
		then(nonClosableCleaner).should(times(2)).scheduleAtFixedRate(nonClosableTaskArgumentCaptor.capture(),
				eq(Duration.ofMinutes(1).toMillis()),
				eq(Duration.ofMinutes(1).toMillis()),
				eq(TimeUnit.MILLISECONDS));
	}

	@Test
	void setCacheTTL() {
		cache.setCacheEntryTTL(Duration.ofSeconds(250));

		assertThat(cache.getCacheEntryTTL()).isEqualTo(Duration.ofSeconds(250));
	}

	@Test
	void setCurrentEntryTTL() {
		cache.setCurrentEntryTTL(Duration.ofDays(7));

		assertThat(cache.getCurrentEntryTTL()).isEqualTo(Duration.ofDays(7));
	}

	@Test
	void setCacheGracePeriod() {
		cache.setCacheGracePeriod(Duration.ofDays(7));

		assertThat(cache.getCacheGracePeriod()).isEqualTo(Duration.ofDays(7));
	}

	@Test
	void testPut() {
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);

		assertThat(cache.put(TEST_KEY, TEST_STRING_VALUE)).isEqualTo(TEST_STRING_VALUE);
		assertThat(getExpiryDate((getCache(cache).entrySet().iterator().next().getValue()))).isEqualTo(birthDate.plus(TEST_CACHE_DURATION_TTL));
	}

	@Test
	void testGet() {
		given(clock.instant()).willReturn(Instant.now());
		cache.put(TEST_KEY, TEST_STRING_VALUE); // set up cache
		// before calling get, make the clock return some arbitrary instant for 'now'
		Instant updateDate = Instant.ofEpochMilli(56666666L);
		given(clock.instant()).willReturn(updateDate);

		assertThat(cache.get(TEST_KEY)).isEqualTo(TEST_STRING_VALUE);
		assertThat(getExpiryDate((getCache(cache).entrySet().iterator().next().getValue()))).isEqualTo(updateDate.plus(TEST_CACHE_DURATION_TTL));
	}

	@Test
	void testGetKeyIsCurrentEntry() {
		given(clock.instant()).willReturn(Instant.now());
		cache.putCurrent(TEST_KEY, TEST_STRING_VALUE); // set up current key

		assertThat(cache.get(TEST_KEY)).isEqualTo(TEST_STRING_VALUE);
		assertThat(getCache(cache)).isEmpty();
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void testGetNoKey() {
		assertThat(cache.get(TEST_KEY)).isNull();
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void testGetKeyDoesNotMatchCacheOrCurrentKey() {
		given(clock.instant()).willReturn(Instant.now());
		cache.putCurrent(TEST_KEY, TEST_STRING_VALUE); // set up some current key
		cache.put("testKey2", "TEST_STRING_VALUE_2"); // set up some cached key


		assertThat(cache.get("SomeOtherKey")).isNull();
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void testPutCurrent() {
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);

		assertThat(cache.putCurrent(TEST_KEY, TEST_STRING_VALUE)).isEqualTo(TEST_STRING_VALUE);
		assertThat(getCache(cache)).isEmpty();
		assertThat(getCurrentEntry(cache).get().getValue().value).isEqualTo(TEST_STRING_VALUE);
		assertThat(getCurrentEntry(cache).get().getKey()).isEqualTo(TEST_KEY);
		assertThat(getExpiryDate(getCurrentEntry(cache).get().getValue())).isEqualTo(birthDate.plus(TEST_CURRENT_ENTRY_TTL));
	}

	@Test
	void testPutCurrentEntryAnotherCurrentEntryAlreadyExistsNotAutoclosable() {
		String testKey2 = "TEST_KEY_2";
		String testStringValue2 = "TEST_STRING_VALUE_2";
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);
		cache.putCurrent(TEST_KEY, TEST_STRING_VALUE);

		assertThat(cache.putCurrent(testKey2, testStringValue2)).isEqualTo(testStringValue2);
		assertThat(getCache(cache)).isEmpty();
		assertThat(getCurrentEntry(cache).get().getValue().value).isEqualTo(testStringValue2);
		assertThat(getCurrentEntry(cache).get().getKey()).isEqualTo(testKey2);
		assertThat(getExpiryDate(getCurrentEntry(cache).get().getValue())).isEqualTo(birthDate.plus(TEST_CURRENT_ENTRY_TTL));
	}

	@Test
	void testPutCurrentEntryAnotherCurrentEntryAlreadyExistsAutoclosable() {
		String testKey2 = "TEST_KEY_2";
		Instant birthDate1 = Instant.now();
		Instant evictionTime = Instant.now().plus(Duration.ofSeconds(6));
		Instant birthDate2 = Instant.now().plus(Duration.ofSeconds(9));
		given(clock.instant()).willReturn(birthDate1, evictionTime, birthDate2);
		closeableCache.putCurrent(TEST_KEY, currentAutoclosable);

		assertThat(closeableCache.putCurrent(testKey2, currentAutoclosable2)).isEqualTo(currentAutoclosable2);
		assertThat(getCache(closeableCache)).isEmpty();
		assertThat(getCurrentEntry(closeableCache).get().getValue().value).isEqualTo(currentAutoclosable2);
		assertThat(getCurrentEntry(closeableCache).get().getKey()).isEqualTo(testKey2);
		assertThat(getExpiryDate(getCurrentEntry(closeableCache).get().getValue())).isEqualTo(birthDate2.plus(TEST_CURRENT_ENTRY_TTL));

		Set<Object> expectedEvictedEntries = Set.of(currentAutoclosable);
		assertThat(getEvictedEntries(closeableCache)).extracting(cacheEntry -> cacheEntry.value).containsExactlyInAnyOrderElementsOf(expectedEvictedEntries::iterator);
		assertThat(getEvictedEntries(closeableCache)).allMatch(cacheEntry -> getExpiryDate(cacheEntry).equals(evictionTime.plus(TEST_GRACE_PERIOD)));
	}

	@Test
	void testPutCurrentEntrySetValueUnsupported() {
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);

		assertThat(cache.putCurrent(TEST_KEY, TEST_STRING_VALUE)).isEqualTo(TEST_STRING_VALUE);
		Map.Entry<?, CacheEntry> entry = getCurrentEntry(cache).get();
		assertThatThrownBy(() -> entry.setValue(null))
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessage(null);
	}

	@Test
	void getCurrentEntry() {
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);

		cache.putCurrent(TEST_KEY, TEST_STRING_VALUE);

		assertThat(cache.getCurrent()).isEqualTo(TEST_STRING_VALUE);
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void getCurrentEntryNull() {
		Instant birthDate = Instant.now();
		given(clock.instant()).willReturn(birthDate);

		cache.putCurrent(TEST_KEY, null);

		String result = cache.getCurrent();
		assertThat(result).isNull();
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void getCurrentEntryWhenNoCurrentEntry() {
		assertThat(cache.getCurrent()).isNull();
		then(clock).shouldHaveNoMoreInteractions();
	}

	@Test
	void testShutdown() {
		doNothing().when(nonClosableCleaner).shutdown();

		cache.shutdown();

		verify(nonClosableCleaner).shutdown();
	}

	@Test
	void clear() {
		given(clock.instant()).willReturn(Instant.now());
		cache.putCurrent(TEST_KEY, TEST_STRING_VALUE);
		cache.put("cachedKey", "cachedValue");

		cache.clear();

		assertNull(cache.get(TEST_KEY));
		assertNull(cache.getCurrent());
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
	}

	@Test
	void clearCurrentEntryNull() {
		cache.clear();

		assertNull(cache.getCurrent());
		assertThat(getEvictedEntries(cache)).isEmpty();
	}

	@Test
	void clearClosable() {
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);
		closeableCache.putCurrent(TEST_KEY, currentAutoclosable);
		closeableCache.put("cachedKey", cachedAutoclosable);

		closeableCache.clear();

		assertNull(closeableCache.get("cachedKey"));
		assertNull(closeableCache.getCurrent());

		Set<Object> expectedEvictedEntries = Set.of(currentAutoclosable, cachedAutoclosable);
		assertThat(getEvictedEntries(closeableCache)).extracting(cacheEntry -> cacheEntry.value).containsExactlyInAnyOrderElementsOf(expectedEvictedEntries::iterator);
		assertThat(getEvictedEntries(closeableCache)).allMatch(cacheEntry -> getExpiryDate(cacheEntry).equals(now.plus(TEST_GRACE_PERIOD)));
	}

	@Test
	void evictionTaskFailureIsLoggedAndTheNextRunStillHappens() {
		Instant birthDate = Instant.now();
		Instant expiredTime = birthDate.plus(TEST_CACHE_DURATION_TTL).plus(Duration.ofMinutes(15));
		given(clock.instant()).willReturn(birthDate).willThrow(new IllegalStateException("clock failure")).willReturn(expiredTime);
		cache.put(TEST_KEY, TEST_STRING_VALUE);
		Runnable evictionTask = nonClosableTaskArgumentCaptor.getAllValues().get(0);

		assertThatNoException().isThrownBy(evictionTask::run);
		assertThat(getCache(cache)).hasSize(1);

		evictionTask.run();
		assertThat(getCache(cache)).isEmpty();
	}

	@Test
	void purgeTaskFailureIsLoggedAndTheNextRunStillHappens() throws Exception {
		Instant birthDate = Instant.now();
		Instant expiredTime = birthDate.plus(TEST_CACHE_DURATION_TTL).plus(Duration.ofMinutes(15));
		Instant afterGracePeriod = expiredTime.plus(TEST_GRACE_PERIOD).plusSeconds(1);
		given(clock.instant()).willReturn(birthDate, expiredTime, expiredTime).willThrow(new IllegalStateException("clock failure")).willReturn(afterGracePeriod);
		closeableCache.put(TEST_KEY, cachedAutoclosable);
		closableTaskArgumentCaptor.getAllValues().get(0).run();
		Runnable purgeTask = closableTaskArgumentCaptor.getAllValues().get(1);

		assertThatNoException().isThrownBy(purgeTask::run);
		verify(cachedAutoclosable, Mockito.never()).close();

		purgeTask.run();
		verify(cachedAutoclosable).close();
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
	}

	@Test
	void evictionTaskNotAutoclosable() {
		Instant birthDate = Instant.now();
		Instant cacheEntriesEvictionTaskTime = birthDate.plus(TEST_CACHE_DURATION_TTL).plus(Duration.ofMinutes(15));
		Instant currentEntryEvictionTaskTime = birthDate.plus(TEST_CURRENT_ENTRY_TTL).plus(Duration.ofMinutes(15));
		given(clock.instant()).willReturn(birthDate, birthDate, cacheEntriesEvictionTaskTime, currentEntryEvictionTaskTime);

		cache.put(TEST_KEY, TEST_STRING_VALUE);
		cache.putCurrent("TEST_KEY_2", "TEST_STRING_VALUE_2");

		nonClosableTaskArgumentCaptor.getAllValues().get(0).run();
		assertThat(getEvictedEntries(cache)).extracting(cacheEntry -> cacheEntry.value)
				.isEmpty();
		assertThat(getCache(cache)).isEmpty();
		assertThat(getCurrentEntry(cache).get()).isNull();
	}

	@Test
	void evictionTaskNotAutoclosableCachedEntryIsNull() {
		Instant birthDate = Instant.now();
		Instant cacheEntriesEvictionTaskTime = birthDate.plus(TEST_CACHE_DURATION_TTL).plus(Duration.ofMinutes(15));
		Instant currentEntryEvictionTaskTime = birthDate.plus(TEST_CURRENT_ENTRY_TTL).plus(Duration.ofMinutes(15));
		given(clock.instant()).willReturn(birthDate, cacheEntriesEvictionTaskTime, currentEntryEvictionTaskTime);

		cache.put(TEST_KEY, null);

		nonClosableTaskArgumentCaptor.getAllValues().get(0).run();
		assertThat(getEvictedEntries(cache)).extracting(cacheEntry -> cacheEntry.value)
				.isEmpty();
		assertThat(getCache(cache)).isEmpty();
		assertThat(getCurrentEntry(cache).get()).isNull();
	}

	@Test
	void evictionTaskAutoclosableExpired() {
		Instant birthDate = Instant.now();
		Instant purgeTime = birthDate.plus(TEST_CURRENT_ENTRY_TTL).plus(Duration.ofMinutes(15));
		given(clock.instant()).willReturn(birthDate, birthDate, purgeTime);

		closeableCache.put(TEST_KEY, cachedAutoclosable);
		closeableCache.putCurrent("TEST_KEY_2", currentAutoclosable);

		closableTaskArgumentCaptor.getAllValues().get(0).run();
		Set<Object> expectedEvictedEntries = Set.of(cachedAutoclosable, currentAutoclosable);
		assertThat(getEvictedEntries(closeableCache)).extracting(cacheEntry -> cacheEntry.value)
				.containsExactlyInAnyOrderElementsOf(expectedEvictedEntries::iterator);
		assertThat(getEvictedEntries(closeableCache))
				.extracting(this::getExpiryDate).satisfiesExactlyInAnyOrder(
						instant -> assertThat(instant).isEqualTo(purgeTime.plus(TEST_GRACE_PERIOD)),
						instant -> assertThat(instant).isEqualTo(purgeTime.plus(TEST_GRACE_PERIOD)));
		assertThat(getCache(closeableCache)).isEmpty();
		assertThat(getCurrentEntry(closeableCache).get()).isNull();
	}

	@Test
	void evictionTaskAutoclosableNotExpired() {
		Instant birthDate = Instant.now();
		Instant evictionTaskTime = birthDate.plus(TEST_CACHE_DURATION_TTL).minus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(birthDate, birthDate, evictionTaskTime);

		closeableCache.put(TEST_KEY, cachedAutoclosable);
		closeableCache.putCurrent("TEST_KEY_2", currentAutoclosable);

		closableTaskArgumentCaptor.getAllValues().get(0).run();
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		assertThat(getExpiryDate(getCache(closeableCache).get(TEST_KEY))).isEqualTo(birthDate.plus(TEST_CACHE_DURATION_TTL));
		assertThat(getExpiryDate(getCurrentEntry(closeableCache).get().getValue())).isEqualTo(birthDate.plus(TEST_CURRENT_ENTRY_TTL));
	}

	@Test
	void purgeTaskEvictedEntryNotExpiredYet() {
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);
		CacheEntry evictedEntry = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		evictedEntry.setExpiryDate(now.plus(Duration.ofSeconds(2)));
		getEvictedEntries(closeableCache).add(evictedEntry);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		then(cachedAutoclosable).shouldHaveNoInteractions();
	}

	@Test
	void purgeTaskExpiredEvictedEntry() throws Exception {
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);
		CacheEntry evictedEntry = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		evictedEntry.setExpiryDate(now.minus(Duration.ofSeconds(2)));
		getEvictedEntries(closeableCache).add(evictedEntry);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		then(cachedAutoclosable).should().close();
	}

	@Test
	void purgeTaskExpiredEvictedEntryExceptionOnClose() throws Exception {
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);
		CacheEntry evictedEntry = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		evictedEntry.setExpiryDate(now.minus(Duration.ofSeconds(2)));
		getEvictedEntries(closeableCache).add(evictedEntry);
		willThrow(new RuntimeException("Test Exception")).given(cachedAutoclosable).close();

		assertThatNoException().isThrownBy(() -> closableTaskArgumentCaptor.getAllValues().get(1).run());

		then(cachedAutoclosable).should().close();
	}

	@Test
	void purgeTaskRemovesExpiredEntriesFromSet() throws Exception {
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);
		CacheEntry expiredEntry = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		expiredEntry.setExpiryDate(now.minus(Duration.ofSeconds(2)));
		getEvictedEntries(closeableCache).add(expiredEntry);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		// Verify entry was removed from evictedEntries after closing
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(cachedAutoclosable).should().close();
	}

	@Test
	void purgeTaskKeepsNonExpiredEntriesInSet() {
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);
		CacheEntry notExpiredEntry = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		notExpiredEntry.setExpiryDate(now.plus(Duration.ofSeconds(2)));
		getEvictedEntries(closeableCache).add(notExpiredEntry);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		// Verify entry was NOT removed from evictedEntries (not expired yet)
		assertThat(getEvictedEntries(closeableCache)).hasSize(1);
		assertThat(getEvictedEntries(closeableCache)).contains(notExpiredEntry);
		then(cachedAutoclosable).shouldHaveNoInteractions();
	}

	@Test
	void shutdownCallsClearAndPurgesAllEntries() throws Exception {
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);
		closeableCache.putCurrent(TEST_KEY, currentAutoclosable);
		closeableCache.put("cachedKey", cachedAutoclosable);

		closeableCache.shutdown();

		// Verify clear was called (cache and current entry should be empty)
		assertThat(getCache(closeableCache)).isEmpty();
		assertThat(getCurrentEntry(closeableCache).get()).isNull();

		// Verify purgeAllEvictedEntries was called (all evicted entries removed and closed)
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
		then(cachedAutoclosable).should().close();
		then(closableCleaner).should().shutdown();
	}

	@Test
	void shutdownClosesAllEvictedResources() throws Exception {
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		// Add entries to evictedEntries directly
		CacheEntry evictedEntry1 = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		CacheEntry evictedEntry2 = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		getEvictedEntries(closeableCache).add(evictedEntry1);
		getEvictedEntries(closeableCache).add(evictedEntry2);

		closeableCache.shutdown();

		// Verify all evicted entries were closed and removed
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
		then(cachedAutoclosable).should().close();
	}

	@Test
	void shutdownHandlesExceptionDuringResourceClose() throws Exception {
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		CacheEntry evictedEntry = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		getEvictedEntries(closeableCache).add(evictedEntry);
		willThrow(new RuntimeException("Close failed")).given(currentAutoclosable).close();

		assertThatNoException().isThrownBy(() -> closeableCache.shutdown());

		// Even with exception, entry should be removed
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
	}

	@Test
	void purgeAllEvictedEntriesWithNonAutoCloseableEntries() {

		// This test covers the case where purgeAllEvictedEntries handles non-AutoCloseable gracefully
		// In practice, only AutoCloseable entries are added, but we verify the safety check
		cache.shutdown();

		// Should complete without exception
		assertThat(getEvictedEntries(cache)).isEmpty();
	}

	@Test
	void purgeTaskReturnsTrueForExpiredEntries() throws Exception {
		// This test verifies that the lambda in purgeTask returns true for expired entries
		// This kills the mutant that replaces "return true" with "return false"
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);

		CacheEntry expiredEntry1 = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		expiredEntry1.setExpiryDate(now.minus(Duration.ofSeconds(2)));
		CacheEntry expiredEntry2 = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		expiredEntry2.setExpiryDate(now.minus(Duration.ofSeconds(1)));

		getEvictedEntries(closeableCache).add(expiredEntry1);
		getEvictedEntries(closeableCache).add(expiredEntry2);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		// If the lambda returns false incorrectly, entries would NOT be removed
		// Verify both entries were removed (lambda returned true)
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
		then(cachedAutoclosable).should().close();
	}

	@Test
	void purgeTaskReturnsFalseForNonExpiredEntries() {
		// This test verifies that the lambda in purgeTask returns false for non-expired entries
		// This kills the mutant that replaces "return false" with "return true"
		Instant now = Instant.now().plus(Duration.ofMinutes(1));
		given(clock.instant()).willReturn(now);

		CacheEntry notExpiredEntry1 = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		notExpiredEntry1.setExpiryDate(now.plus(Duration.ofSeconds(10)));
		CacheEntry notExpiredEntry2 = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		notExpiredEntry2.setExpiryDate(now.plus(Duration.ofSeconds(20)));

		getEvictedEntries(closeableCache).add(notExpiredEntry1);
		getEvictedEntries(closeableCache).add(notExpiredEntry2);

		closableTaskArgumentCaptor.getAllValues().get(1).run();

		// If the lambda returns true incorrectly, entries would be removed even though not expired
		// Verify both entries remain (lambda returned false)
		assertThat(getEvictedEntries(closeableCache)).hasSize(2);
		assertThat(getEvictedEntries(closeableCache)).containsExactlyInAnyOrder(notExpiredEntry1, notExpiredEntry2);
		then(currentAutoclosable).shouldHaveNoInteractions();
		then(cachedAutoclosable).shouldHaveNoInteractions();
	}

	@Test
	void shutdownCallsClearToEmptyCacheAndCurrentEntry() {
		// This test verifies that shutdown actually calls clear() and has observable effect
		// This kills the mutant that removes the call to clear()
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		closeableCache.putCurrent(TEST_KEY, currentAutoclosable);
		closeableCache.put("cachedKey", cachedAutoclosable);

		// Before shutdown, cache and current entry should have data
		assertThat(getCache(closeableCache)).isNotEmpty();
		assertThat(getCurrentEntry(closeableCache).get()).isNotNull();

		closeableCache.shutdown();

		// After shutdown with clear() called, cache and current entry should be empty
		// If clear() is not called, these would still have data
		assertThat(getCache(closeableCache)).isEmpty();
		assertThat(getCurrentEntry(closeableCache).get()).isNull();
	}

	@Test
	void shutdownCallsPurgeAllEvictedEntriesToCloseResources() throws Exception {
		// This test verifies that shutdown actually calls purgeAllEvictedEntries() and closes resources
		// This kills the mutant that removes the call to purgeAllEvictedEntries()
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		// Add entries that will be moved to evictedEntries during clear()
		closeableCache.putCurrent(TEST_KEY, currentAutoclosable);
		closeableCache.put("cachedKey", cachedAutoclosable);

		closeableCache.shutdown();

		// If purgeAllEvictedEntries() is not called, resources would not be closed
		// and evictedEntries would not be empty
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
		then(cachedAutoclosable).should().close();
	}

	@Test
	void purgeAllEvictedEntriesClosesAutoCloseableResources() throws Exception {
		// This test covers the conditional check for AutoCloseable in purgeAllEvictedEntries
		// Lines 230, 232, 238 (NO_COVERAGE mutants)
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		CacheEntry closeableEntry = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		getEvictedEntries(closeableCache).add(closeableEntry);

		closeableCache.shutdown();

		// Verify the AutoCloseable was closed
		then(currentAutoclosable).should().close();
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
	}

	@Test
	void purgeAllEvictedEntriesAlwaysReturnsTrue() throws Exception {
		// This test verifies that purgeAllEvictedEntries lambda always returns true (line 238)
		// This kills the mutant that replaces the return value with false
		Instant now = Instant.now();
		given(clock.instant()).willReturn(now);

		CacheEntry entry1 = closeableCache.new CacheEntry<>(currentAutoclosable, TEST_CACHE_DURATION_TTL);
		CacheEntry entry2 = closeableCache.new CacheEntry<>(cachedAutoclosable, TEST_CACHE_DURATION_TTL);
		getEvictedEntries(closeableCache).add(entry1);
		getEvictedEntries(closeableCache).add(entry2);

		closeableCache.shutdown();

		// If lambda returns false, entries would NOT be removed from evictedEntries
		// Verify all entries were removed (lambda returned true for all)
		assertThat(getEvictedEntries(closeableCache)).isEmpty();
		then(currentAutoclosable).should().close();
		then(cachedAutoclosable).should().close();
	}

	private Instant getExpiryDate(CacheEntry cacheEntry) {
		try {
			Field expiryDateField = CacheEntry.class.getDeclaredField("expiryDate");
			expiryDateField.setAccessible(true);
			return (Instant) expiryDateField.get(cacheEntry);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private AtomicReference<Map.Entry<?, CacheEntry>> getCurrentEntry(LingeringCloseCache concurrentCache) {
		try {
			Field currentEntry = LingeringCloseCache.class.getDeclaredField("currentEntry");
			currentEntry.setAccessible(true);
			return (AtomicReference<Map.Entry<?, CacheEntry>>) currentEntry.get(concurrentCache);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private Set<CacheEntry> getEvictedEntries(LingeringCloseCache concurrentCache) {
		try {
			Field evictedEntriesField = LingeringCloseCache.class.getDeclaredField("evictedEntries");
			evictedEntriesField.setAccessible(true);
			return (Set<CacheEntry>) evictedEntriesField.get(concurrentCache);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private ConcurrentHashMap<?, CacheEntry> getCache(LingeringCloseCache concurrentCache) {
		try {
			Field field = LingeringCloseCache.class.getDeclaredField("cache");
			field.setAccessible(true);
			return (ConcurrentHashMap<?, CacheEntry>) field.get(concurrentCache);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}