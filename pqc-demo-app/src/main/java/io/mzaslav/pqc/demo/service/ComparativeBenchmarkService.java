package io.mzaslav.pqc.demo.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.mzaslav.pqc.algorithm.ClassicalSigAlgorithm;
import io.mzaslav.pqc.algorithm.MlDsaParameterSet;
import io.mzaslav.pqc.demo.metrics.MetricNames;
import io.mzaslav.pqc.hybrid.HybridSigner;
import io.mzaslav.pqc.signature.SignatureKeyPair;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Cross-algorithm benchmarking service used to populate the comparison
 * dashboard (classical vs. PQC-only vs. hybrid).
 * <p>
 * For each scheme, the service spins up a dedicated {@link HybridSigner},
 * runs the configured number of sign/verify cycles and records timing,
 * memory and size metrics into Micrometer with a human-readable
 * {@code algorithm} tag.
 *
 * @author mzaslav
 * @since 1.0
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ComparativeBenchmarkService {

    private final MeterRegistry meterRegistry;

    /**
     * Runs the benchmark for every supported scheme (classical, PQC-only,
     * and hybrid combinations).
     *
     * @param iterations sign/verify cycles per scheme
     */
    public void runAllBenchmarks(int iterations) {
        log.info("Starting ALL benchmarks with {} iterations...", iterations);
        runBenchmark("[1] Classical (Ed25519)", HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.ED25519), iterations);
        runBenchmark("[2] Classical (ECDSA_P256)", HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.ECDSA_P256), iterations);
        runBenchmark("[3] Classical (RSA_2048)", HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.RSA_2048), iterations);
        runBenchmark("[4] PQC Only (ML-DSA-44)", HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_44), iterations);
        runBenchmark("[5] PQC Only (ML-DSA-65)", HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_65), iterations);
        runBenchmark("[6] PQC Only (ML-DSA-87)", HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_87), iterations);
        runBenchmark("[7] HYBRID (Ed25519 + ML-DSA-65)", HybridSigner.create(ClassicalSigAlgorithm.ED25519, MlDsaParameterSet.ML_DSA_65), iterations);
        runBenchmark("[8] HYBRID (ECDSA_P256 + ML-DSA-65)", HybridSigner.create(ClassicalSigAlgorithm.ECDSA_P256, MlDsaParameterSet.ML_DSA_65), iterations);
        runBenchmark("[9] HYBRID (RSA_2048 + ML-DSA-65)", HybridSigner.create(ClassicalSigAlgorithm.RSA_2048, MlDsaParameterSet.ML_DSA_65), iterations);
        log.info("ALL benchmarks finished!");
    }

    public void runBenchmark(String readableName, HybridSigner signer, int iterations) {
        DistributionSummary memorySignSummary = meterRegistry.summary(MetricNames.MEMORY_USED_BYTES, "algorithm", readableName, "operation", "sign");
        DistributionSummary efficiencySummary = meterRegistry.summary(MetricNames.TOKEN_EFFICIENCY_PERCENT, "algorithm", readableName);
        DistributionSummary tokenSizeSummary = meterRegistry.summary(MetricNames.TOKEN_SIZE_BYTES, "algorithm", readableName);
        DistributionSummary sigSizeSummary = meterRegistry.summary(MetricNames.SIGNATURE_SIZE_BYTES, "algorithm", readableName);

        log.info("Starting benchmark for: {} ({} iterations)", readableName, iterations);

        SignatureKeyPair keyPair = signer.generateKeyPair();
        byte[] payload = "{\"sub\":\"benchmark-test\",\"role\":\"admin\",\"exp\":1735689600}".getBytes(StandardCharsets.UTF_8);
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);

        for (int i = 0; i < iterations; i++) {
            long beforeSignUsed = usedMemory();
            Timer.Sample signSample = Timer.start(meterRegistry);

            byte[] signature = signer.sign(keyPair, payload);

            signSample.stop(Timer.builder(MetricNames.SIGN_DURATION)
                    .tag("algorithm", readableName).register(meterRegistry));

            long signUsedMemory = Math.max(0, usedMemory() - beforeSignUsed);
            memorySignSummary.record(signUsedMemory); // ЗАПИСЬ ПАМЯТИ

            if (i == 0) {
                String encodedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
                int tokenSize = encodedPayload.length() + 1 + encodedSig.length();
                double efficiency = calculateEfficiency(encodedPayload.length(), tokenSize);

                tokenSizeSummary.record(tokenSize);
                sigSizeSummary.record(signature.length);
                efficiencySummary.record(efficiency);
            }

            Timer.Sample verifySample = Timer.start(meterRegistry);
            boolean isValid = signer.verify(keyPair, payload, signature);
            verifySample.stop(Timer.builder(MetricNames.VERIFY_DURATION)
                    .tag("algorithm", readableName).register(meterRegistry));

            Counter.builder(MetricNames.OPERATIONS_TOTAL)
                    .tag("algorithm", readableName)
                    .tag("operation", "verify")
                    .tag("status", isValid ? "success" : "failure")
                    .register(meterRegistry).increment();

            Counter.builder(MetricNames.OPERATIONS_TOTAL)
                    .tag("algorithm", readableName)
                    .tag("operation", "sign")
                    .tag("status", "success")
                    .register(meterRegistry).increment();
        }
    }

    private static long usedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static double calculateEfficiency(int payloadSize, int tokenSize) {
        if (tokenSize == 0) return 0.0;
        return (double) payloadSize / tokenSize * 100.0;
    }
}