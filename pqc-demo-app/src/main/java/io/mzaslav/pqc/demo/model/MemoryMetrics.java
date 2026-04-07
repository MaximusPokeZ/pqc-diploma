package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class MemoryMetrics {
    private final long count;
    private final double meanBytes;
    private final double maxBytes;
    private final double meanKB;
    private final double maxKB;
    private final double totalBytes;

    public static MemoryMetrics empty() {
        return MemoryMetrics.builder()
                .count(0)
                .meanBytes(0.0)
                .maxBytes(0.0)
                .meanKB(0.0)
                .maxKB(0.0)
                .totalBytes(0.0)
                .build();
    }
}
