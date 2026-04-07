package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SizeMetrics {
    private final long count;
    private final double mean;
    private final double max;
    private final double total;

    public static SizeMetrics empty() {
        return SizeMetrics.builder()
                .count(0)
                .mean(0.0)
                .max(0.0)
                .total(0.0)
                .build();
    }
}
