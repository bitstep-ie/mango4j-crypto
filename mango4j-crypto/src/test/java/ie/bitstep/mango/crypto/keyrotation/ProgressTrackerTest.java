package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.keyrotation.ProgressTracker;
import ie.bitstep.mango.crypto.keyrotation.exceptions.TooManyFailuresException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class ProgressTrackerTest {

	private static final int MAX_FAILURE_COUNT = 10;

	private ProgressTracker progressTracker;

	@BeforeEach
	void setUp() {
		progressTracker = new ProgressTracker(MAX_FAILURE_COUNT);
	}

	@Test
	void constructor() {
		assertThat(getMaxFailureCountPerExecution()).isEqualTo(MAX_FAILURE_COUNT);
	}

	@Test
	void getNumberOfRecordsUpdated() {
		assertThat(progressTracker.getNumberOfRecordsProcessed()).isZero();
	}

	@Test
	void incrementRecordsProcessed() {
		setNumberOfRecordsProcessed(2);

		progressTracker.incrementRecordsProcessed();

		assertThat(progressTracker.getNumberOfRecordsProcessed()).isEqualTo(3);
	}

	@Test
	void incrementBatchesProcessed() {
		setNumberOfBatchesProcessed(2);

		progressTracker.incrementBatchesProcessed();

		assertThat(progressTracker.getNumberOfBatchesProcessed()).isEqualTo(3);
	}

	@Test
	void incrementNumberOfRecordsFailedCount() {
		progressTracker.incrementNumberOfRecordsFailed();

		assertThat(getNumberOfRecordsFailed()).isEqualTo(1);
	}

	@Test
	void incrementNumberOfRecordsFailedCountEqualToMaxFailureAllowedCount() {
		setProcessingFailureCount(MAX_FAILURE_COUNT - 1);
		progressTracker.incrementNumberOfRecordsFailed();

		assertThat(getNumberOfRecordsFailed()).isEqualTo(10);
	}

	@Test
	void incrementNumberOfRecordsFailedWhenOverLimit() {
		setProcessingFailureCount(MAX_FAILURE_COUNT);

		assertThatThrownBy(() -> progressTracker.incrementNumberOfRecordsFailed())
			.isInstanceOf(TooManyFailuresException.class)
			.hasMessage("Max errors threshold of 10 per execution exceeded while processing records, failure count=11");
	}

	@Test
	void incrementNumberOfRecordsFailedWhenFailureCountIsZero() {
		progressTracker = new ProgressTracker(0);

		assertThatThrownBy(progressTracker::incrementNumberOfRecordsFailed)
			.isInstanceOf(TooManyFailuresException.class)
			.hasMessage("Max errors threshold of 0 per execution exceeded while processing records, failure count=1");
	}

	@Test
	void incrementProcessingFailureCountWhenMaxLimitIsLessThanZero() {
		progressTracker = new ProgressTracker(-1);

		progressTracker.incrementNumberOfRecordsFailed();

		assertThat(getNumberOfRecordsFailed()).isEqualTo(1);
	}

	@Test
	void getNumberOfRecordsFailedTest() {
		progressTracker.incrementNumberOfRecordsFailed();

		assertThat(progressTracker.getNumberOfRecordsFailed()).isEqualTo(1);
	}

	private int getNumberOfRecordsFailed() {
		try {
			Field numberOfRecordsFailedField = ProgressTracker.class.getDeclaredField("numberOfRecordsFailed");
			numberOfRecordsFailedField.setAccessible(true);
			return (int) numberOfRecordsFailedField.get(progressTracker);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private int getMaxFailureCountPerExecution() {
		try {
			Field maxFailureCountPerExecutionField = ProgressTracker.class.getDeclaredField("maxFailureCountPerExecution");
			maxFailureCountPerExecutionField.setAccessible(true);
			return (int) maxFailureCountPerExecutionField.get(progressTracker);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void setProcessingFailureCount(int numberOfRecordsFailed) {
		try {
			Field numberOfRecordsFailedField = ProgressTracker.class.getDeclaredField("numberOfRecordsFailed");

			numberOfRecordsFailedField.setAccessible(true);
			numberOfRecordsFailedField.set(progressTracker, numberOfRecordsFailed);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void setNumberOfRecordsProcessed(int numberOfRecordsProcessed) {
		try {
			Field numberOfRecordsProcessedField = ProgressTracker.class.getDeclaredField("numberOfRecordsProcessed");
			numberOfRecordsProcessedField.setAccessible(true);
			numberOfRecordsProcessedField.set(progressTracker, numberOfRecordsProcessed);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private void setNumberOfBatchesProcessed(int numberOfBatchesProcessed) {
		try {
			Field numberOfBatchesProcessedField = ProgressTracker.class.getDeclaredField("numberOfBatchesProcessed");
			numberOfBatchesProcessedField.setAccessible(true);
			numberOfBatchesProcessedField.set(progressTracker, numberOfBatchesProcessed);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}