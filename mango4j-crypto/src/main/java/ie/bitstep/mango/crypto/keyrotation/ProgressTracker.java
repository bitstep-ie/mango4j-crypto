package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.keyrotation.exceptions.TooManyFailuresException;

import java.util.function.Consumer;

import static java.util.Objects.requireNonNull;

public class ProgressTracker {

	private final int maxFailureCountPerExecution;
	private final ProgressTracker progressTrackerDelegate;

	private int numberOfRecordsProcessed = 0;
	private int numberOfRecordsFailed = 0;
	private int numberOfBatchesProcessed = 0;

	/**
	 * Creates a progress tracker with a failure threshold.
	 *
	 * @param maxFailureCountPerExecution the maximum failures allowed per execution
	 */
	public ProgressTracker(int maxFailureCountPerExecution) {
		this.maxFailureCountPerExecution = maxFailureCountPerExecution;
		this.progressTrackerDelegate = null;
	}

	public ProgressTracker(ProgressTracker progressTrackerDelegate) {
		requireNonNull(progressTrackerDelegate, "progressTrackerDelegate cannot be null");
		this.maxFailureCountPerExecution = progressTrackerDelegate.maxFailureCountPerExecution;
		this.progressTrackerDelegate = progressTrackerDelegate;
	}

	private void executeFunctionOnProgressTrackerDelegate(Consumer<ProgressTracker> methodExecutor) {
		if (progressTrackerDelegate != null) {
			methodExecutor.accept(progressTrackerDelegate);
		}
	}

	/**
	 * Increments the processed records count.
	 */
	public void incrementNumberOfRecordsProcessed() {
		numberOfRecordsProcessed += 1;
		executeFunctionOnProgressTrackerDelegate(ProgressTracker::incrementNumberOfRecordsProcessed);
	}

	/**
	 * Increments the processed batches count.
	 */
	public void incrementNumberOfBatchesProcessed() {
		numberOfBatchesProcessed += 1;
		executeFunctionOnProgressTrackerDelegate(ProgressTracker::incrementNumberOfBatchesProcessed);
	}

	/**
	 * Increments failed records and throws if the threshold is exceeded.
	 */
	public void incrementNumberOfRecordsFailed() {
		// Increment locally first so the child stays consistent even if the delegate throws.
		++numberOfRecordsFailed;
		executeFunctionOnProgressTrackerDelegate(ProgressTracker::incrementNumberOfRecordsFailed);
		if (maxFailureCountPerExecution >= 0 && numberOfRecordsFailed > maxFailureCountPerExecution) {
			throw new TooManyFailuresException(
				String.format("Max errors threshold of %d per execution exceeded while processing records, failure count=%d",
					maxFailureCountPerExecution, numberOfRecordsFailed));
		}
	}

	/**
	 * Returns the number of batches processed.
	 *
	 * @return the batches processed count
	 */
	public int getNumberOfBatchesProcessed() {
		return numberOfBatchesProcessed;
	}

	/**
	 * Returns the number of records failed.
	 *
	 * @return the failed records count
	 */
	public int getNumberOfRecordsFailed() {
		return numberOfRecordsFailed;
	}

	/**
	 * Returns the number of records processed.
	 *
	 * @return the processed records count
	 */
	public int getNumberOfRecordsProcessed() {
		return numberOfRecordsProcessed;
	}
}
