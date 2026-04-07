package io.mzaslav.pqc.demo.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class OverheadMetrics {
    private final double tokenSizeIncrease;
    private final double signatureSizeIncrease;
    private final double signingTimeIncrease;
    private final double verificationTimeIncrease;
    private final double efficiencyDecrease;
    private final double memorySignIncrease;
    private final double memoryVerifyIncrease;
}
