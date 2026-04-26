package io.mzaslav.pqc.demo.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.mzaslav.pqc.demo.metrics.MetricNames;
import io.mzaslav.pqc.hybrid.HybridSigner;
import io.mzaslav.pqc.signature.SignatureKeyPair;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Demo JWT-style token service that uses the auto-configured
 * {@link HybridSigner} to sign and verify payloads while recording
 * Micrometer metrics for each operation.
 * <p>
 * Tokens use the simple format {@code base64url(payload).base64url(signature)} -
 * sufficient for benchmarking signature schemes without dragging in a JOSE
 * library that does not yet support ML-DSA natively.
 *
 * @author mzaslav
 * @since 1.0
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final MeterRegistry meterRegistry;

    private final HybridSigner hybridSigner;

    private SignatureKeyPair serverKeyPair;

    @PostConstruct
    public void init() {
        this.serverKeyPair = hybridSigner.generateKeyPair();
    }

    /**
     * Builds a signed token for the given claims and records timing,
     * size, efficiency and memory metrics under the active algorithm tag.
     *
     * @param claims arbitrary key/value claims to embed in the payload
     * @return the encoded token in {@code payload.signature} form
     */
    public String issueToken(Map<String, Object> claims) {
        String actualAlgo = hybridSigner.toString();

        Timer.Sample sample = Timer.start(meterRegistry);
        long beforeUsed = usedMemory();
        try {
            String payload = claims.toString() + ":" + System.nanoTime();
            byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);

            byte[] signature = hybridSigner.sign(serverKeyPair, payloadBytes);

            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadBytes);
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            String token = encodedPayload + "." + encodedSignature;

            int signatureSize = signature.length;
            int tokenSize = token.length();

            DistributionSummary.builder(MetricNames.TOKEN_SIZE_BYTES)
                    .tag("algorithm", actualAlgo).register(meterRegistry).record(tokenSize);
            DistributionSummary.builder(MetricNames.SIGNATURE_SIZE_BYTES)
                    .tag("algorithm", actualAlgo).register(meterRegistry).record(signatureSize);
            DistributionSummary.builder(MetricNames.TOKEN_EFFICIENCY_PERCENT)
                    .tag("algorithm", actualAlgo).register(meterRegistry).record(calculateEfficiency(encodedPayload.length(), tokenSize));
            Counter.builder(MetricNames.OPERATIONS_TOTAL)
                    .tag("algorithm", actualAlgo).tag("operation", "sign").tag("status", "success")
                    .register(meterRegistry).increment();

            return token;
        } finally {
            recordMemory(actualAlgo, "sign", beforeUsed);
            sample.stop(Timer.builder(MetricNames.SIGN_DURATION)
                    .tag("algorithm", actualAlgo).register(meterRegistry));
        }
    }

    /**
     * Verifies a token issued by {@link #issueToken(Map)} and records
     * verification timing, memory and outcome counters.
     *
     * @param token     the token to verify
     * @param algorithm metric tag (informational, the actual scheme comes from {@link HybridSigner})
     * @return {@code true} if the signature checks out
     */
    public boolean verifyToken(String token, String algorithm) {
        String actualAlgo = hybridSigner.toString();
        Timer.Sample sample = Timer.start(meterRegistry);
        long beforeUsed = usedMemory();
        boolean success = false;
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 2) return false;

            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[0]);
            byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[1]);

            success = hybridSigner.verify(serverKeyPair, payloadBytes, signatureBytes);
            return success;

        } catch (Exception ex) {
            return false;
        } finally {
            recordMemory(actualAlgo, "verify", beforeUsed);
            sample.stop(Timer.builder(MetricNames.VERIFY_DURATION)
                    .tag("algorithm", actualAlgo).register(meterRegistry));

            Counter.builder(MetricNames.OPERATIONS_TOTAL)
                    .tag("algorithm", actualAlgo).tag("operation", "verify")
                    .tag("status", success ? "success" : "signature_invalid")
                    .register(meterRegistry).increment();
        }
    }

    private static double calculateEfficiency(int payloadSize, int tokenSize) {
        if (tokenSize == 0) {
            return 0.0;
        }
        return (double) payloadSize / tokenSize * 100.0;
    }

    private static int signatureSizeFor(String algorithm) {
        if (algorithm == null) {
            return 256;
        }
        String normalized = algorithm.toLowerCase();
        if (normalized.contains("ml") || normalized.contains("dsa")) {
            return ThreadLocalRandom.current().nextInt(2300, 2800);
        }
        return ThreadLocalRandom.current().nextInt(240, 360);
    }

    private void recordMemory(String algorithm, String operation, long beforeUsed) {
        long used = Math.max(0, usedMemory() - beforeUsed);
        DistributionSummary.builder(MetricNames.MEMORY_USED_BYTES)
                .baseUnit("bytes")
                .tag("algorithm", algorithm)
                .tag("operation", operation)
                .register(meterRegistry)
                .record(used);
    }

    private static long usedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
