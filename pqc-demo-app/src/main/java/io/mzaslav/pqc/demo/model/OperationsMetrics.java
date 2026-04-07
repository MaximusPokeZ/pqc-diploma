package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class OperationsMetrics {
    private final long totalSigned;
    private final long totalVerified;
    private final double verificationSuccessRate;
    private final long verificationFailures;
}
