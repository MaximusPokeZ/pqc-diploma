package io.mzaslav.pqc.demo.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.distribution.HistogramSnapshot;
import io.mzaslav.pqc.demo.metrics.MetricNames;
import io.mzaslav.pqc.demo.model.AlgorithmMetrics;
import io.mzaslav.pqc.demo.model.EfficiencyMetrics;
import io.mzaslav.pqc.demo.model.MemoryMetrics;
import io.mzaslav.pqc.demo.model.OperationsMetrics;
import io.mzaslav.pqc.demo.model.OverheadMetrics;
import io.mzaslav.pqc.demo.model.SizeMetrics;
import io.mzaslav.pqc.demo.model.TimingMetrics;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Reads Micrometer meters tagged with a particular algorithm and assembles
 * a structured {@link AlgorithmMetrics} snapshot for the REST API and the
 * Grafana dashboard.
 * <p>
 * Also exposes {@link #calculateOverhead(AlgorithmMetrics, AlgorithmMetrics)}
 * to compute relative overhead between two algorithms (e.g. classical vs.
 * hybrid).
 *
 * @author mzaslav
 * @since 1.0
 */
@Service
@RequiredArgsConstructor
public class MetricsSnapshotService {

    private final MeterRegistry meterRegistry;

    /**
     * Builds a snapshot of all relevant meters for a single algorithm tag.
     *
     * @param algorithm the {@code algorithm} tag value to filter on
     * @return a populated {@link AlgorithmMetrics} (with zero values for absent meters)
     */
    public AlgorithmMetrics extractMetrics(String algorithm) {
        Timer signingTimer = meterRegistry.find(MetricNames.SIGN_DURATION)
                .tag("algorithm", algorithm)
                .timer();

        Timer verificationTimer = meterRegistry.find(MetricNames.VERIFY_DURATION)
                .tag("algorithm", algorithm)
                .timer();

        DistributionSummary tokenSize = meterRegistry.find(MetricNames.TOKEN_SIZE_BYTES)
                .tag("algorithm", algorithm)
                .summary();

        DistributionSummary signatureSize = meterRegistry.find(MetricNames.SIGNATURE_SIZE_BYTES)
                .tag("algorithm", algorithm)
                .summary();

        DistributionSummary efficiency = meterRegistry.find(MetricNames.TOKEN_EFFICIENCY_PERCENT)
                .tag("algorithm", algorithm)
                .summary();

        DistributionSummary memorySign = meterRegistry.find(MetricNames.MEMORY_USED_BYTES)
                .tag("algorithm", algorithm)
                .tag("operation", "sign")
                .summary();

        DistributionSummary memoryVerify = meterRegistry.find(MetricNames.MEMORY_USED_BYTES)
                .tag("algorithm", algorithm)
                .tag("operation", "verify")
                .summary();

        Counter signCounter = meterRegistry.find(MetricNames.OPERATIONS_TOTAL)
                .tag("algorithm", algorithm)
                .tag("operation", "sign")
                .tag("status", "success")
                .counter();

        Counter verifySuccessCounter = meterRegistry.find(MetricNames.OPERATIONS_TOTAL)
                .tag("algorithm", algorithm)
                .tag("operation", "verify")
                .tag("status", "success")
                .counter();

        Counter verifyFailCounter = meterRegistry.find(MetricNames.OPERATIONS_TOTAL)
                .tag("algorithm", algorithm)
                .tag("operation", "verify")
                .tag("status", "signature_invalid")
                .counter();

        return AlgorithmMetrics.builder()
                .algorithm(algorithm)
                .signing(buildTimingMetrics(signingTimer))
                .verification(buildTimingMetrics(verificationTimer))
                .tokenSize(buildSizeMetrics(tokenSize))
                .signatureSize(buildSizeMetrics(signatureSize))
                .efficiency(buildEfficiencyMetrics(efficiency))
                .memorySign(buildMemoryMetrics(memorySign))
                .memoryVerify(buildMemoryMetrics(memoryVerify))
                .operations(buildOperationsMetrics(signCounter, verifySuccessCounter, verifyFailCounter))
                .build();
    }

    private TimingMetrics buildTimingMetrics(Timer timer) {
        if (timer == null) {
            return TimingMetrics.empty();
        }

        HistogramSnapshot snapshot = timer.takeSnapshot();
        Map<Double, Double> percentiles = extractPercentiles(snapshot);

        return TimingMetrics.builder()
                .count(timer.count())
                .mean(round(timer.mean(TimeUnit.MILLISECONDS)))
                .max(round(timer.max(TimeUnit.MILLISECONDS)))
                .p50(percentiles.getOrDefault(0.5, 0.0))
                .p95(percentiles.getOrDefault(0.95, 0.0))
                .p99(percentiles.getOrDefault(0.99, 0.0))
                .totalTime(round(timer.totalTime(TimeUnit.MILLISECONDS)))
                .build();
    }

    private MemoryMetrics buildMemoryMetrics(DistributionSummary summary) {
        if (summary == null) {
            return MemoryMetrics.empty();
        }

        double meanBytes = summary.mean();
        double maxBytes = summary.max();

        return MemoryMetrics.builder()
                .count(summary.count())
                .meanBytes(round(meanBytes))
                .maxBytes(round(maxBytes))
                .meanKB(round(meanBytes / 1024.0))
                .maxKB(round(maxBytes / 1024.0))
                .totalBytes(round(summary.totalAmount()))
                .build();
    }

    private Map<Double, Double> extractPercentiles(HistogramSnapshot snapshot) {
        Map<Double, Double> percentiles = new HashMap<>();
        for (var valueAtPercentile : snapshot.percentileValues()) {
            double percentile = valueAtPercentile.percentile();
            double value = round(valueAtPercentile.value(TimeUnit.MILLISECONDS));
            percentiles.put(percentile, value);
        }
        return percentiles;
    }

    private SizeMetrics buildSizeMetrics(DistributionSummary summary) {
        if (summary == null) {
            return SizeMetrics.empty();
        }

        return SizeMetrics.builder()
                .count(summary.count())
                .mean(round(summary.mean()))
                .max(round(summary.max()))
                .total(round(summary.totalAmount()))
                .build();
    }

    private EfficiencyMetrics buildEfficiencyMetrics(DistributionSummary summary) {
        if (summary == null || summary.count() == 0) {
            return EfficiencyMetrics.empty();
        }

        HistogramSnapshot snapshot = summary.takeSnapshot();
        double min = summary.mean();
        double max = summary.mean();
        for (var valueAtPercentile : snapshot.percentileValues()) {
            double value = valueAtPercentile.value();
            min = Math.min(min, value);
            max = Math.max(max, value);
        }

        return EfficiencyMetrics.builder()
                .meanPercent(round(summary.mean()))
                .minPercent(round(min))
                .maxPercent(round(max))
                .build();
    }

    private OperationsMetrics buildOperationsMetrics(
            Counter signCounter,
            Counter verifySuccessCounter,
            Counter verifyFailCounter
    ) {
        long signCount = signCounter != null ? (long) signCounter.count() : 0;
        long verifySuccess = verifySuccessCounter != null ? (long) verifySuccessCounter.count() : 0;
        long verifyFail = verifyFailCounter != null ? (long) verifyFailCounter.count() : 0;

        long totalVerifications = verifySuccess + verifyFail;
        double successRate = totalVerifications > 0
                ? (double) verifySuccess / totalVerifications * 100.0
                : 0.0;

        return OperationsMetrics.builder()
                .totalSigned(signCount)
                .totalVerified(totalVerifications)
                .verificationSuccessRate(round(successRate))
                .verificationFailures(verifyFail)
                .build();
    }

    /**
     * Computes relative overhead (in percent) of {@code compared} versus
     * {@code baseline} across timing, size, memory and efficiency dimensions.
     *
     * @param baseline reference metrics (e.g. classical algorithm)
     * @param compared metrics being evaluated (e.g. hybrid algorithm)
     * @return per-dimension overhead values
     */
    public OverheadMetrics calculateOverhead(AlgorithmMetrics baseline, AlgorithmMetrics compared) {
        return OverheadMetrics.builder()
                .tokenSizeIncrease(calculatePercentageIncrease(
                        baseline.getTokenSize().getMean(),
                        compared.getTokenSize().getMean()))
                .signatureSizeIncrease(calculatePercentageIncrease(
                        baseline.getSignatureSize().getMean(),
                        compared.getSignatureSize().getMean()))
                .signingTimeIncrease(calculatePercentageIncrease(
                        baseline.getSigning().getMean(),
                        compared.getSigning().getMean()))
                .verificationTimeIncrease(calculatePercentageIncrease(
                        baseline.getVerification().getMean(),
                        compared.getVerification().getMean()))
                .efficiencyDecrease(calculatePercentageDecrease(
                        baseline.getEfficiency().getMeanPercent(),
                        compared.getEfficiency().getMeanPercent()))
                .memorySignIncrease(calculatePercentageIncrease(
                        baseline.getMemorySign().getMeanBytes(),
                        compared.getMemorySign().getMeanBytes()))
                .memoryVerifyIncrease(calculatePercentageIncrease(
                        baseline.getMemoryVerify().getMeanBytes(),
                        compared.getMemoryVerify().getMeanBytes()))
                .build();
    }

    private double calculatePercentageIncrease(double baseline, double compared) {
        if (baseline == 0) {
            return 0.0;
        }
        return round(((compared - baseline) / baseline) * 100.0);
    }

    private double calculatePercentageDecrease(double baseline, double compared) {
        if (baseline == 0) {
            return 0.0;
        }
        return round(((baseline - compared) / baseline) * 100.0);
    }

    private double round(double value) {
        return Math.round(value * 100.0) / 100.0;
    }
}
