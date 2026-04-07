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

@Service
@RequiredArgsConstructor
@Slf4j
public class ComparativeBenchmarkService {

    private final MeterRegistry meterRegistry;

    public void runAllBenchmarks(int iterations) {
        runBenchmark(
                "[1] Classical (Ed25519)",
                HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.ED25519),
                iterations
        );

        runBenchmark(
                "[2] Classical (ECDSA_P256)",
                HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.ECDSA_P256),
                iterations
        );

        runBenchmark(
                "[3] Classical (RSA_2048)",
                HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.RSA_2048),
                iterations
        );

        runBenchmark(
                "[4] PQC Only (ML-DSA-44)",
                HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_44),
                iterations
        );

        runBenchmark(
                "[5] PQC Only (ML-DSA-65)",
                HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_65),
                iterations
        );

        runBenchmark(
                "[6] PQC Only (ML-DSA-87)",
                HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_87),
                iterations
        );

        runBenchmark(
                "[7] HYBRID (Ed25519 + ML-DSA-65)",
                HybridSigner.create(ClassicalSigAlgorithm.ED25519, MlDsaParameterSet.ML_DSA_65),
                iterations
        );

        runBenchmark(
                "[8] HYBRID (ECDSA_P256 + ML-DSA-65)",
                HybridSigner.create(ClassicalSigAlgorithm.ECDSA_P256, MlDsaParameterSet.ML_DSA_65),
                iterations
        );

        runBenchmark(
                "[9] HYBRID (RSA_2048 + ML-DSA-65)",
                HybridSigner.create(ClassicalSigAlgorithm.RSA_2048, MlDsaParameterSet.ML_DSA_65),
                iterations
        );
    }

    public void runBenchmark(String readableName, HybridSigner signer, int iterations) {
        log.info("Starting benchmark for: {} ({} iterations)", readableName, iterations);

        SignatureKeyPair keyPair = signer.generateKeyPair();
        byte[] payload = "{\"sub\":\"benchmark-test\",\"role\":\"admin\",\"exp\":1735689600}".getBytes(StandardCharsets.UTF_8);
        String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);

        for (int i = 0; i < iterations; i++) {
            Timer.Sample signSample = Timer.start(meterRegistry);
            byte[] signature = signer.sign(keyPair, payload);
            signSample.stop(Timer.builder(MetricNames.SIGN_DURATION)
                    .tag("algorithm", readableName).register(meterRegistry));

            if (i == 0) {
                String encodedSig = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
                int tokenSize = encodedPayload.length() + 1 + encodedSig.length();
                DistributionSummary.builder(MetricNames.TOKEN_SIZE_BYTES)
                        .tag("algorithm", readableName).register(meterRegistry).record(tokenSize);
                DistributionSummary.builder(MetricNames.SIGNATURE_SIZE_BYTES)
                        .tag("algorithm", readableName).register(meterRegistry).record(signature.length);
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
        }

        log.info("Benchmark finished for: {}", readableName);
    }
}