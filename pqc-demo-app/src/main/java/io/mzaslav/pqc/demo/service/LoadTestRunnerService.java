package io.mzaslav.pqc.demo.service;

import io.mzaslav.pqc.demo.model.LoadTestResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class LoadTestRunnerService {

    private final JwtService jwtService;

    public LoadTestResult runLoadTest(String algorithm, int iterations) {
        log.info("Starting load test for {}: {} iterations", algorithm, iterations);
        int successfulVerifications = 0;
        long startTime = System.currentTimeMillis();

        Map<String, Object> claims = Map.of("sub", "stress-test", "role", "benchmark");

        for (int i = 0; i < iterations; i++) {
            try {
                String token = jwtService.issueToken(claims);
                if (jwtService.verifyToken(token, algorithm)) {
                    successfulVerifications++;
                }
            } catch (Exception e) {
                log.error("Error in iteration {}", i, e);
            }
        }

        long totalTime = System.currentTimeMillis() - startTime;
        return new LoadTestResult(algorithm, iterations, successfulVerifications, totalTime);
    }
}
