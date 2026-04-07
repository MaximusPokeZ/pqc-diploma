package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class EfficiencyMetrics {
    private final double meanPercent;
    private final double minPercent;
    private final double maxPercent;

    public static EfficiencyMetrics empty() {
        return EfficiencyMetrics.builder()
                .meanPercent(0.0)
                .minPercent(0.0)
                .maxPercent(0.0)
                .build();
    }
}
