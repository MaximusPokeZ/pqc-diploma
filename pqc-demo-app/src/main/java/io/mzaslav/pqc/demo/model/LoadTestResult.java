package io.mzaslav.pqc.demo.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LoadTestResult {
    private final String algorithm;
    private final int iterations;
    private final int successfulVerifications;
    private final long totalTimeMillis;
}
