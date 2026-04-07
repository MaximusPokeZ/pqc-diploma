package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class TimingMetrics {
    private final long count;
    private final double mean;
    private final double max;
    private final double p50;
    private final double p95;
    private final double p99;
    private final double totalTime;

    public static TimingMetrics empty() {
        return TimingMetrics.builder()
                .count(0)
                .mean(0.0)
                .max(0.0)
                .p50(0.0)
                .p95(0.0)
                .p99(0.0)
                .totalTime(0.0)
                .build();
    }
}
