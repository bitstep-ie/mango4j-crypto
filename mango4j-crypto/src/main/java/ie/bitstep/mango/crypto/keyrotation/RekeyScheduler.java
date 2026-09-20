package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.RekeyCryptoShield;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.exceptions.NonTransientCryptoException;
import ie.bitstep.mango.crypto.hmac.DoubleHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.HmacStrategy;
import ie.bitstep.mango.crypto.hmac.ListHmacFieldStrategy;
import ie.bitstep.mango.crypto.hmac.SingleHmacFieldStrategy;
import ie.bitstep.mango.crypto.keyrotation.exceptions.TooManyFailuresException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Function;
import java.util.stream.Collector;

import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_OFF;
import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_ON;
import static ie.bitstep.mango.crypto.keyrotation.RekeyEvent.Type.REKEY_FINISHED;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toList;

/**
 * <b>Warning!!!</b> This class is currently experimental and is expected to go through several more iterations of both redesign
 * and refactoring. If you can read this message, don't use in production code just yet.
 */
@SuppressWarnings("unused")
public class RekeyScheduler {
	private static final String[] ORDINAL_SUFFIXES = new String[]{"th", "st", "nd", "rd", "th", "th", "th", "th", "th", "th"};

	private final System.Logger logger = System.getLogger(RekeyScheduler.class.getName());
	private final RekeySchedulerConfig rekeySchedulerConfig;

	public RekeyScheduler(RekeySchedulerConfig rekeySchedulerConfig) {
		this.rekeySchedulerConfig = rekeySchedulerConfig;
		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(this::rekeyTenants, this.rekeySchedulerConfig.getInitialDelay(), this.rekeySchedulerConfig.getRekeyCheckInterval(), this.rekeySchedulerConfig.getRekeyTimeUnits());
	}

	private void rekeyTenants() {
		try {
			logger.log(TRACE, "Beginning rekey job");
			Map<String, List<CryptoKey>> allEncryptionKeys = new HashMap<>();
			for (CryptoKey cryptoKey : rekeySchedulerConfig.getCryptoShield().getCryptoKeyProvider().getAllCryptoKeys()) {
				// HashMap allows null keys so if the app doesn't have tenants then cryptokey.getTenantId() can return null and
				// this functionality will still work fine
				allEncryptionKeys.computeIfAbsent(cryptoKey.getTenantId(), tenantId -> new ArrayList<>()).add(cryptoKey);
			}
			if (allEncryptionKeys.isEmpty()) {
				logger.log(TRACE, "No keys found to rekey");
			}

			for (Map.Entry<String, List<CryptoKey>> tenantsCryptoKeysEntry : allEncryptionKeys.entrySet()) {
				try {
					if (tenantsCryptoKeysEntry.getValue().stream().anyMatch(cryptoKey -> cryptoKey.getRekeyMode() != null)) {
						rekeyTenant(tenantsCryptoKeysEntry.getKey(), tenantsCryptoKeysEntry.getValue());
					} else {
						logger.log(DEBUG, "No keys need rekeying{0}", tenantLogString(tenantsCryptoKeysEntry.getKey()));
					}
				} catch (TooManyFailuresException e) {
					logger.log(ERROR, "Too many failures occurred trying to rekey records", e);
				}
			}
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to rekey records", e);
		}
	}

	private void rekeyTenant(String tenantId, List<CryptoKey> tenantCryptoKeys) {
		if (tenantCryptoKeys.size() <= 1) {
			logger.log(ERROR, "There are no Crypto Keys defined{0}", tenantLogString(tenantId));
			return;
		}

		if (tenantCryptoKeys.stream().anyMatch(cryptoKey -> cryptoKey.getCreatedDate() == null)) {
			logger.log(ERROR, "Created date was not set to a valid value on some Crypto Keys{0}.....skipping rekey for this tenant", tenantLogString(tenantId));
			return;
		}

		List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending = tenantCryptoKeys.stream()
				.sorted(Comparator.comparing(CryptoKey::getCreatedDate).reversed())
				.toList();

		// TODO: Currently we re-encrypt and re-HMAC separately which isn't very performant. Once this automated rekey code is
		// settled and out of beta we need to come back and make that these are done together, especially for entities that have both
		// encrypted data and HMACs
		try {
			reEncrypt(tenantId, justEncryptionKeys(tenantAllCryptoKeysSortedByDateDescending));
		} catch (RekeySkipException e) {
			logger.log(INFO, e.getMessage());
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to rekey encryption keys{0}", tenantLogString(tenantId));
		}

		try {
			reHmac(tenantId, justHmacKeys(tenantAllCryptoKeysSortedByDateDescending));
		} catch (RekeySkipException e) {
			logger.log(INFO, e.getMessage());
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to rekey HMAC keys{0}", tenantLogString(tenantId));
		}
	}

	private void reEncrypt(String tenantId, List<CryptoKey> tenantEncryptionKeysSortedByDateDescending) {
		logger.log(TRACE, "Beginning re-encrypt for tenant {0}", tenantId);
		Map<String, List<CryptoKey>> tenantEncryptionKeysGroupedByKeySelectorSortedByDateDescending = getEncryptionKeysGroupedByKeySelectorSortedByDateDescending(tenantId, tenantEncryptionKeysSortedByDateDescending);
		long totalRecordsRekeyedForTenant = 0;
		for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
			List<RekeyServiceTaskHolder> rekeyServiceTaskHolders = new ArrayList<>();
			if (rekeySchedulerConfig.getCryptoShield().getAnnotatedEntityManager().getFieldsToEncrypt(rekeyService.getEntityType()).isEmpty()) {
				logger.log(DEBUG, "Entity {0} does not have encrypted fields, so nothing to rekey for it", rekeyService.getEntityType().getSimpleName());
				continue;
			}

			tenantEncryptionKeysGroupedByKeySelectorSortedByDateDescending.forEach((keySelector, tenantsCryptoKeysForThisSelectorSortedByDateDescending) -> {
				CryptoKey latestCryptoKeyForKeySelector = tenantsCryptoKeysForThisSelectorSortedByDateDescending.get(0);
				if (latestCryptoKeyForKeySelector.getRekeyMode() == KEY_ON) {
					logger.log(TRACE, "RekeyMode is set to {0} on the latest encryption key{1}{2}", KEY_ON, keySelectorLogString(keySelector), tenantLogString(tenantId));
					rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOnRecordSupplier(latestCryptoKeyForKeySelector),
							rekeyService,
							latestCryptoKeyForKeySelector,
							latestCryptoKeyForKeySelector,
							null));
				} else if (tenantsCryptoKeysForThisSelectorSortedByDateDescending.stream().anyMatch(key -> key.getRekeyMode() == KEY_OFF)) {
					logger.log(TRACE, "RekeyMode is set to {0} on {2} encryption keys{3}{1}", KEY_OFF, tenantLogString(tenantId), tenantEncryptionKeysSortedByDateDescending.stream().filter(cryptoKey -> cryptoKey.getRekeyMode() == KEY_OFF).count(), keySelectorLogString(keySelector));
					tenantsCryptoKeysForThisSelectorSortedByDateDescending.forEach(cryptoKey -> {
						if (cryptoKey.getRekeyMode() == KEY_OFF) {
							rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOffRecordSupplier(cryptoKey),
									rekeyService,
									cryptoKey,
									latestCryptoKeyForKeySelector,
									null));
						}
					});
				} else {
					logger.log(TRACE, "No Re-keying needed for entity {0}{1}", rekeyService.getEntityType().getSimpleName(), tenantLogString(tenantId));
				}
			});
			if (!rekeyServiceTaskHolders.isEmpty()) {
				// TODO: A progress tracker is currently created for each entity but the maxFailureCountPerExecution is intended to be 'per run' (over all entities). So this needs to be updated to create a single progress tracker
				// for the entire run and pass it to each entity's rekey service task holder. But for now, just create a new one for each entity.
				ProgressTracker finishedProgressForThisEntity = rekeyEntity(rekeyServiceTaskHolders);
				logger.log(INFO, "Full re-key of all records for entity {0} has been completed{1}. Total of {2} records rekeyed for this entity", rekeyService.getEntityType().getSimpleName(), tenantLogString(tenantId), finishedProgressForThisEntity.getNumberOfRecordsProcessed());
				totalRecordsRekeyedForTenant += finishedProgressForThisEntity.getNumberOfRecordsProcessed();
			}
		}
		logger.log(INFO, "Full re-key of all records{0} has been completed. Total of {1} records rekeyed by this job", tenantLogString(tenantId), totalRecordsRekeyedForTenant);
		cleanupRedundantKeys(tenantEncryptionKeysGroupedByKeySelectorSortedByDateDescending);
	}

	private void cleanupRedundantKeys(Map<String, List<CryptoKey>> tenantEncryptionKeysGroupedByKeySelectorSortedByDateDescending) {
		for (List<CryptoKey> tenantEncryptionKeys : tenantEncryptionKeysGroupedByKeySelectorSortedByDateDescending.values()) {
			boolean shouldDeleteAllNonLatestKeys = false;
			for (int count = 0; count < tenantEncryptionKeys.size(); count++) {
				if (count == 0 && tenantEncryptionKeys.get(0).getRekeyMode() == KEY_ON) {
					shouldDeleteAllNonLatestKeys = true;
				} else if (shouldDeleteAllNonLatestKeys || (count > 0 && tenantEncryptionKeys.get(count).getRekeyMode() == KEY_OFF)) {
					logger.log(DEBUG, "No application instances are using the following deprecated encryption key anymore (and any records which previously used it have been re-keyed to the latest encryption key), so we''ll delete it: {0}", tenantEncryptionKeys.get(count));
					removeKey(tenantEncryptionKeys.get(count));
				}

			}
		}
	}

	private CryptoKey getLatestEncryptionKey(String tenantId, List<CryptoKey> tenantEncryptionKeysSortedByDateDescending) {
		if (tenantEncryptionKeysSortedByDateDescending.isEmpty() || tenantEncryptionKeysSortedByDateDescending.size() == 1) {
			throw new RekeySkipException(String.format("%s encryption keys were found%s (minimum of 2 needed).....skipping the currently scheduled encryption rekey tasks for this tenant ", tenantEncryptionKeysSortedByDateDescending.size(), tenantLogString(tenantId)));
		}
		CryptoKey tenantLatestEncryptionKey = tenantEncryptionKeysSortedByDateDescending.get(0);
		if (tenantLatestEncryptionKey.getRekeyMode() == KEY_OFF) {
			throw new RekeySkipException(String.format("RekeyMode is set to %1$s on the latest encryption key%2$s. This is a misconfiguration, the latest encryption key should not be set to %1$s!!.....skipping the currently scheduled encryption rekey task for this tenant", KEY_OFF, tenantLogString(tenantId)));
		}
		if (tenantLatestEncryptionKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now())) {
			throw new RekeySkipException(String.format("Some application instances might not be using the new encryption key yet%s.....skipping the currently scheduled encryption rekey task for this tenant", tenantLogString(tenantId)));
		}
		return tenantLatestEncryptionKey;
	}

	private Map<String, List<CryptoKey>> getEncryptionKeysGroupedByKeySelectorSortedByDateDescending(String tenantId, List<CryptoKey> tenantEncryptionKeysSortedByDateDescending) {
		Map<String, List<CryptoKey>> cryptoKeysGroupedByKeySelector = tenantEncryptionKeysSortedByDateDescending.stream().collect(keySelectorCollector());
		if (tenantEncryptionKeysSortedByDateDescending.isEmpty() || cryptoKeysGroupedByKeySelector.entrySet()
				.stream().anyMatch(keySelectorCryptoKeyGroup -> keySelectorCryptoKeyGroup.getValue().size() == 1)) {
			throw new RekeySkipException(String.format("No encryption keys were found%s (minimum of 2 needed).....skipping the currently scheduled encryption rekey tasks for this tenant ", tenantLogString(tenantId)));
		}

		// don't bother with a key selector group if none of its CryptoKeys have a rekey mode set
		cryptoKeysGroupedByKeySelector.entrySet()
				.removeIf(keySelectorEntry -> keySelectorEntry.getValue().stream().noneMatch(cryptoKey -> cryptoKey.getRekeyMode() != null));

		for (Map.Entry<String, List<CryptoKey>> keySelectorEntry : cryptoKeysGroupedByKeySelector.entrySet()) {
			boolean anyKeySelectorGroupsDontHaveEnoughKeys = keySelectorEntry.getValue().stream().anyMatch(cryptoKey -> keySelectorEntry.getValue().size() == 1);
			// TODO: Revisit this to investigate handling of keys that were already involved in a previous and successful rekey but where the rekey mode was just never set back to null.
			// That's probably gonna be quite common so this check will probably need to be relaxed to allow for that scenario. But for now, let's just throw an exception and skip the rekey for this tenant.
			if (anyKeySelectorGroupsDontHaveEnoughKeys) {
				throw new RekeySkipException(String.format("%s encryption keys were found with key selector %s%s (minimum of 2 needed).....skipping the currently scheduled encryption rekey tasks for this tenant ", tenantEncryptionKeysSortedByDateDescending.size(), keySelectorEntry.getKey(), tenantLogString(tenantId)));
			}
		}

		cryptoKeysGroupedByKeySelector.forEach((keySelector, cryptoKeys) -> {
			if (cryptoKeys.get(0).getRekeyMode() == KEY_OFF) {
				throw new RekeySkipException(String.format("RekeyMode is set to %1$s on the latest encryption key%2$s with selector %3$s. This is a misconfiguration, the latest encryption key for a particular key selector should not be set to %1$s!!.....skipping the currently scheduled encryption rekey task for this tenant", KEY_OFF, tenantLogString(tenantId), keySelector));
			}
			if (cryptoKeys.get(0).getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now())) {
				throw new RekeySkipException(String.format("Some application instances might not be using the new encryption keys yet%s.....skipping the currently scheduled encryption rekey task for this tenant", tenantLogString(tenantId)));
			}
		});
		return cryptoKeysGroupedByKeySelector;
	}

	private static Collector<CryptoKey, ?, Map<String, List<CryptoKey>>> keySelectorCollector() {
		return groupingBy(cryptoKey -> cryptoKey.getKeySelector() == null ? "" : cryptoKey.getKeySelector());
	}

	private static List<CryptoKey> olderKeys(List<CryptoKey> tenantEncryptionKeysSortedByDateDescending) {
		return tenantEncryptionKeysSortedByDateDescending.subList(1, tenantEncryptionKeysSortedByDateDescending.size());
	}

	private static <T> T last(List<T> list) {
		return list.get(list.size() - 1);
	}

	private static List<CryptoKey> justEncryptionKeys(List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		return getKeysByUsage(tenantAllCryptoKeysSortedByDateDescending, CryptoKeyUsage.ENCRYPTION);
	}

	private static List<CryptoKey> justHmacKeys(List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		return getKeysByUsage(tenantAllCryptoKeysSortedByDateDescending, CryptoKeyUsage.HMAC);
	}

	private static List<CryptoKey> getKeysByUsage(List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending, CryptoKeyUsage cryptoKeyUsage) {
		return tenantAllCryptoKeysSortedByDateDescending.stream()
				.filter(cryptoKey -> cryptoKey.getUsage() == cryptoKeyUsage)
				.toList();
	}

	private static String tenantLogString(String tenantId) {
		return tenantId == null ? "" : " for tenant " + tenantId;
	}

	private static String keySelectorLogString(String keySelector) {
		return "".equals(keySelector) ? "" : " for key selector " + keySelector;
	}

	private void reHmac(String tenantId, List<CryptoKey> tenantHmacKeysSortedByDateDescending) {
		logger.log(TRACE, "Beginning re-hmac for tenant {0}", tenantId);
		validateHmacKeys(tenantId, tenantHmacKeysSortedByDateDescending);
		long totalHmacRecordsRekeyedForTenant = 0;
		for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
			List<RekeyServiceTaskHolder> hmacRekeyServiceTaskHolders = generateHmacRekeyServiceTasks(rekeyService, tenantHmacKeysSortedByDateDescending);
			if (!hmacRekeyServiceTaskHolders.isEmpty()) {
				ProgressTracker finishedProgressForThisEntity = rekeyEntity(hmacRekeyServiceTaskHolders);
				logger.log(INFO, "Full HMAC re-key of all records for entity {0} has been completed{1}. Total of {2} records rekeyed for this entity", rekeyService.getEntityType().getSimpleName(), tenantLogString(tenantId), finishedProgressForThisEntity.getNumberOfRecordsProcessed());
				totalHmacRecordsRekeyedForTenant += finishedProgressForThisEntity.getNumberOfRecordsProcessed();
			}
		}
		logger.log(INFO, "Full HMAC re-key of all records{0} has been completed. Total of {1} records rekeyed by this job", tenantLogString(tenantId), totalHmacRecordsRekeyedForTenant);
		// TODO: Eventually support cipher groups for HMACs also but for now, just cleanup the HMAC keys for the default Ciphergroup (which has an empty string as its keySelector)
		cleanupRedundantKeys(Map.of("", tenantHmacKeysSortedByDateDescending));
	}

	private void validateHmacKeys(String tenantId, List<CryptoKey> tenantHmacKeysSortedByDateDescending) {
		if (tenantHmacKeysSortedByDateDescending.isEmpty() || tenantHmacKeysSortedByDateDescending.size() == 1) {
			throw new RekeySkipException(String.format("%s HMAC keys were found%s (minimum of 2 needed).....skipping the currently scheduled HMAC rekey tasks for this tenant ", tenantHmacKeysSortedByDateDescending.size(), tenantLogString(tenantId)));
		} else if (tenantHmacKeysSortedByDateDescending.subList(1, tenantHmacKeysSortedByDateDescending.size() - 1).stream().anyMatch(cryptoKey -> cryptoKey.getRekeyMode() == KEY_ON)) {
			throw new RekeySkipException(String.format("Some older HMAC keys have a rekey mode of %1$s. Only the latest key can be %1$s.....skipping the currently scheduled HMAC rekey tasks for this tenant", KEY_ON));
		} else if (tenantHmacKeysSortedByDateDescending.get(0).getRekeyMode() == KEY_OFF) {
			// can't key off the latest key
			throw new RekeySkipException(String.format("The latest HMAC key has a rekey mode of %1$s. You cannot set the latest key to %1$s.....skipping the currently scheduled HMAC rekey tasks for this tenant", KEY_OFF));
		} else if (tenantHmacKeysSortedByDateDescending.stream()
				.anyMatch(cryptoKey -> cryptoKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now()))) {
			throw new RekeySkipException(String.format("Some application instances might not be using some of the HMAC keys yet{0}....." +
							"skipping the currently scheduled HMAC rekey tasks%s",
					tenantLogString(tenantId)));
		}
	}

	private List<RekeyServiceTaskHolder> generateHmacRekeyServiceTasks(RekeyService<?> rekeyService, List<CryptoKey> tenantHmacKeysSortedByDateDescending) {
		List<RekeyServiceTaskHolder> rekeyServiceTaskHolders = new ArrayList<>();
		CryptoKey keyThatTriggeredTheRekey;
		Optional<HmacStrategy> hmacStrategy = rekeySchedulerConfig.getCryptoShield().getAnnotatedEntityManager().getHmacStrategy(rekeyService.getEntityType());
		if (hmacStrategy.isEmpty()) {
			throw new RekeySkipException(String.format("No HMAC strategy found for %s.", rekeyService.getEntityType().getSimpleName()));
		}

		CryptoKey latestHmacKey = tenantHmacKeysSortedByDateDescending.get(0);
		CryptoKey oldestHmacKey = last(tenantHmacKeysSortedByDateDescending);
		if (latestHmacKey.getRekeyMode() == KEY_ON) {
			keyThatTriggeredTheRekey = latestHmacKey;
		} else if (oldestHmacKey.getRekeyMode() == KEY_OFF) {
			keyThatTriggeredTheRekey = oldestHmacKey;
		} else {
			throw new RekeySkipException("No HMAC keys found to trigger HMAC rekey job");
		}


		if (SingleHmacFieldStrategy.class.isAssignableFrom(hmacStrategy.get().getClass())) {
			if (keyThatTriggeredTheRekey.getRekeyMode() == KEY_OFF) {
				rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOffRecordSupplier(keyThatTriggeredTheRekey),
						rekeyService,
						keyThatTriggeredTheRekey,
						null,
						latestHmacKey));
			} else if (keyThatTriggeredTheRekey.getRekeyMode() == KEY_ON) {
				rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOnRecordSupplier(keyThatTriggeredTheRekey),
						rekeyService,
						keyThatTriggeredTheRekey,
						null,
						latestHmacKey));
			}
		} else if (DoubleHmacFieldStrategy.class.isAssignableFrom(hmacStrategy.get().getClass())) {
			rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOnRecordSupplier(latestHmacKey),
					rekeyService,
					keyThatTriggeredTheRekey,
					null,
					latestHmacKey));
		} else if (ListHmacFieldStrategy.class.isAssignableFrom(hmacStrategy.get().getClass())) {
			if (keyThatTriggeredTheRekey.getRekeyMode() == KEY_OFF) {
				CryptoKey mostRecentNonKeyOffHmacKey = getMostRecentNonKeyOffHmacKey(tenantHmacKeysSortedByDateDescending);
				rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOnRecordSupplier(mostRecentNonKeyOffHmacKey),
						rekeyService,
						keyThatTriggeredTheRekey,
						null,
						mostRecentNonKeyOffHmacKey));
			} else if (keyThatTriggeredTheRekey.getRekeyMode() == KEY_ON) {
				rekeyServiceTaskHolders.add(new RekeyServiceTaskHolder(keyOnRecordSupplier(keyThatTriggeredTheRekey),
						rekeyService,
						keyThatTriggeredTheRekey,
						null,
						keyThatTriggeredTheRekey));
			}
		}
		return rekeyServiceTaskHolders;
	}

	private static CryptoKey getMostRecentNonKeyOffHmacKey(List<CryptoKey> tenantHmacKeysSortedByDateDescending) {
		ListIterator<CryptoKey> listIterator = tenantHmacKeysSortedByDateDescending.listIterator(tenantHmacKeysSortedByDateDescending.size());
		while (listIterator.hasPrevious()) {
			CryptoKey cryptoKey = listIterator.previous();
			if (cryptoKey.getRekeyMode() != KEY_OFF) {
				return cryptoKey;
			}
		}
		// shouldn't be possible to get here
		throw new NonTransientCryptoException("There were no keys to key onto!");
	}

	private boolean doAnyEncryptedRecordsNeedRekeying(Function<RekeyService<?>, List<?>> recordsNeedingRekeyedFunction) {
		List<?> recordsNeedingRekeyed;
		boolean doAnyRecordsNeedRekeying = false;
		for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
			try {
				recordsNeedingRekeyed = getRecords(rekeyService, recordsNeedingRekeyedFunction);
				if (recordsNeedingRekeyed != null && !recordsNeedingRekeyed.isEmpty()) {
					doAnyRecordsNeedRekeying = true;
					break;
				}
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to get records from RekeyService<{0}>", rekeyService.getEntityType());
			}
		}
		return doAnyRecordsNeedRekeying;
	}

	private boolean doAnyRecordsNotHaveAHmacWithThisKey(CryptoKey tenantHmacKey) {
		boolean doAnyRecordsNeedRekeying = false;
		for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
			List<?> recordsNeedingRekeyed = getRecords(rekeyService, keyOnRecordSupplier(tenantHmacKey));
			if (recordsNeedingRekeyed != null && !recordsNeedingRekeyed.isEmpty()) {
				doAnyRecordsNeedRekeying = true;
				break;
			}
		}
		return doAnyRecordsNeedRekeying;
	}

	private List<?> getRecords(RekeyService<?> rekeyService, Function<RekeyService<?>, List<?>> recordsNeedingRekeyedFunction) {
		List<?> recordsNeedingRekeyed = null;
		try {
			recordsNeedingRekeyed = recordsNeedingRekeyedFunction.apply(rekeyService);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to get records from RekeyService<{0}>", rekeyService.getEntityType());
		}
		return recordsNeedingRekeyed;
	}

	private static Function<RekeyService<?>, List<?>> keyOnRecordSupplier(CryptoKey cryptoKey) {
		return (rekeyService) -> rekeyService.findRecordsNotUsingCryptoKey(cryptoKey);
	}

	private static Function<RekeyService<?>, List<?>> keyOffRecordSupplier(CryptoKey cryptoKey) {
		return (rekeyService) -> rekeyService.findRecordsUsingCryptoKey(cryptoKey);
	}

	@SuppressWarnings("BusyWait")
	private ProgressTracker rekeyEntity(List<RekeyServiceTaskHolder> rekeyServiceCipherGroupTaskHolders) {
		ProgressTracker entityRekeyProgressTracker = new ProgressTracker(rekeySchedulerConfig.getMaximumToleratedFailuresPerExecution());
		if (rekeyServiceCipherGroupTaskHolders == null || rekeyServiceCipherGroupTaskHolders.isEmpty()) {
			return entityRekeyProgressTracker;
		}

		// TODO - currently this approach does one key at a time in a way that if there are multiple keys in separate cipher groups that have triggered the rekey, it will do them one at a time.
		// This is not ideal and should be refactored to handle multiple keys that have triggered the rekey in a more efficient way.
		rekeyServiceCipherGroupTaskHolders.forEach((rekeyServiceTaskHolder) -> {
			logger.log(DEBUG, "Checking for records to re-key for entity {0} and Crypto Key {1}", rekeyServiceTaskHolder.rekeyService.getEntityType().getName(), rekeyServiceTaskHolder.keyThatTriggeredTheRekey);
			RekeyCryptoShield rekeyCryptoShield = new RekeyCryptoShield(rekeySchedulerConfig.getCryptoShield(), rekeyServiceTaskHolder.encryptionKeyToKeyOnto, rekeyServiceTaskHolder.hmacKeyToKeyOnto);
			while (!rekeyBatch(rekeyServiceTaskHolder.rekeyService.getEntityType(), rekeyServiceTaskHolder.rekeyService, entityRekeyProgressTracker, rekeyCryptoShield, rekeyServiceTaskHolder.recordsSupplier)) {
				if (!Duration.ZERO.equals(rekeySchedulerConfig.getBatchInterval())) {
					try {
						logger.log(DEBUG, "Waiting for {0} milliseconds before re-keying another batch of records for entity {1}", rekeySchedulerConfig.getBatchInterval(), rekeyServiceTaskHolder.rekeyService.getEntityType().getName());
						Thread.sleep(rekeySchedulerConfig.getBatchInterval().toMillis());
					} catch (InterruptedException e) {
						logger.log(ERROR, String.format("An error occurred waiting to re-key the next batch of records for entity %s....cancelling this re-key task", rekeyServiceTaskHolder.rekeyService.getEntityType().getName()), e);
						Thread.currentThread().interrupt();
						return;
					}
				}
			}
		});

		logger.log(INFO, "Re-key complete for {0}", rekeyServiceCipherGroupTaskHolders.get(0).rekeyService.getEntityType().getName());
		RekeyEvent rekeyFinishedEvent = new RekeyEvent();
		rekeyFinishedEvent.setRekeyServiceClass(rekeyServiceCipherGroupTaskHolders.get(0).getClass());
		rekeyFinishedEvent.setCryptoKeysThatTriggeredTheRekey(rekeyServiceCipherGroupTaskHolders.stream().map(rekeyServiceTaskHolder -> rekeyServiceTaskHolder.keyThatTriggeredTheRekey).collect(toList()));
		rekeyFinishedEvent.setType(REKEY_FINISHED);
		rekeyFinishedEvent.setProgressTracker(entityRekeyProgressTracker);
		rekeyServiceCipherGroupTaskHolders.get(0).rekeyService.notify(rekeyFinishedEvent);
		return entityRekeyProgressTracker;
	}

	/**
	 * @return true if there were no records in this batch to process, meaning that we're finished re-keying this entity. False otherwise.
	 */
	private boolean rekeyBatch(Class<?> entityClass, RekeyService<?> rekeyService, ProgressTracker progressTracker,
							   RekeyCryptoShield rekeyCryptoShield, Function<RekeyService<?>, List<?>> recordsSupplier) {
		progressTracker.incrementBatchesProcessed();
		List<?> recordsToRekey = recordsSupplier.apply(rekeyService);
		if (recordsToRekey == null || recordsToRekey.isEmpty()) {
			logger.log(DEBUG, "No more records to re-key for entity {0}", entityClass.getName());
			return true;
		}

		logger.log(DEBUG, "Found {0} records to re-key for entity {1}", recordsToRekey.size(), entityClass.getName());
		for (Object entity : recordsToRekey) {
			rekeyEntity(entity, progressTracker, rekeyCryptoShield);
		}
		logger.log(DEBUG, "{0} records in batch {1} re-keyed for entity {2}....saving",
				progressTracker.getNumberOfRecordsProcessed() - progressTracker.getNumberOfRecordsFailed(),
				progressTracker.getNumberOfBatchesProcessed(), entityClass.getName());
		try {
			rekeyService.save(recordsToRekey);
		} catch (Exception e) {
			progressTracker.incrementNumberOfRecordsFailed();
			logger.log(WARNING, "An error occurred trying to save the {0} batch of records for entity {1}....skipping record",
					convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()), entityClass.getName());
		}
		logger.log(DEBUG, () -> String.format("%s re-keyed records successfully saved for %s batch for entity %s (%s failed)",
				progressTracker.getNumberOfRecordsProcessed() - progressTracker.getNumberOfRecordsFailed(), convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()),
				entityClass.getName(), progressTracker.getNumberOfRecordsFailed()));
		return false;
	}

	private void rekeyEntity(Object entity, ProgressTracker progressTracker, RekeyCryptoShield rekeyCryptoShield) {
		progressTracker.incrementRecordsProcessed();
		try {
			logger.log(TRACE, () -> String.format("Re-keying %s record in batch %s",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), progressTracker.getNumberOfBatchesProcessed()));
			try {
				rekeyCryptoShield.decrypt(entity);
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to decrypt entity");
				throw new RuntimeException(e);
			}
			try {
				rekeyCryptoShield.encrypt(entity);
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to re-encrypt entity");
				throw new RuntimeException(e);
			}
			logger.log(TRACE, () -> String.format("%s record in batch %s re-keyed successfully",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), progressTracker.getNumberOfBatchesProcessed()));
		} catch (Exception e) {
			progressTracker.incrementNumberOfRecordsFailed();
			logger.log(WARNING, "An error occurred trying to re-key the {0} record in the {1} batch of records for entity {2}....skipping record",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()), entity.getClass().getName());
		}
	}

	private void removeKey(CryptoKey tenantsDeprecatedCryptoKey) {
		try {
			logger.log(INFO, "Notifying the application to mark the following Crypto key as deleted {0}", tenantsDeprecatedCryptoKey);
			rekeySchedulerConfig.getRekeyCryptoKeyManager().markKeyForDeletion(tenantsDeprecatedCryptoKey);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to mark the Crypto key for deletion {}", tenantsDeprecatedCryptoKey);
		}
	}

	private static String convertToOrdinal(int i) {
		return switch (i % 100) {
			case 11, 12, 13 -> i + "th";
			default -> i + ORDINAL_SUFFIXES[i % 10];
		};
	}

	private Instant now() {
		return rekeySchedulerConfig.getClock().instant();
	}

	private record RekeyServiceTaskHolder(
			Function<RekeyService<?>, List<?>> recordsSupplier,
			RekeyService<?> rekeyService,
			CryptoKey keyThatTriggeredTheRekey,
			CryptoKey encryptionKeyToKeyOnto,
			// All HMAC rekeys seem to essentially be single key KEY_ON processes so this probably doesn't need to be a list
			CryptoKey hmacKeyToKeyOnto) {
	}

	private record RekeyServiceTaskHolderV2(
			Function<RekeyService<?>, List<?>> recordsSupplier,
			RekeyService<?> rekeyService,
			Map<String, List<CryptoKey>> keysThatTriggeredTheRekeyByKeySelector,
			Map<String, CryptoKey> encryptionKeyToKeyOnto,
			// All HMAC rekeys seem to essentially be single key KEY_ON processes so this probably doesn't need to be a list
			CryptoKey hmacKeyToKeyOnto) {
	}

	private static class RekeySkipException extends RuntimeException {
		public RekeySkipException(String message) {
			super(message);
		}
	}
}








