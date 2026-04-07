package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AlgorithmMetrics {
    private final String algorithm;
    private final TimingMetrics signing;
    private final TimingMetrics verification;
    private final SizeMetrics tokenSize;
    private final SizeMetrics signatureSize;
    private final EfficiencyMetrics efficiency;
    private final MemoryMetrics memorySign;
    private final MemoryMetrics memoryVerify;
    private final OperationsMetrics operations;
}
