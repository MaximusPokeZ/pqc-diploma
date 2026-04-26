package io.mzaslav.pqc.demo.controller;

import io.mzaslav.pqc.demo.config.LoadTestProperties;
import io.mzaslav.pqc.demo.model.LoadTestRequest;
import io.mzaslav.pqc.demo.model.LoadTestResult;
import io.mzaslav.pqc.demo.service.LoadTestRunnerService;
import io.mzaslav.pqc.demo.service.RunAllToggleService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST controller exposing load-test entry points used by the demo.
 * <p>
 * Provides:
 * <ul>
 *   <li>{@code POST /load-test/run} - run a single benchmark with a chosen algorithm and iteration count</li>
 *   <li>{@code GET  /load-test/defaults} - return the default benchmark parameters</li>
 *   <li>{@code POST /load-test/run-all} - toggle a periodic comparative benchmark across all schemes</li>
 * </ul>
 *
 * @author mzaslav
 * @since 1.0
 */
@RestController
@RequestMapping("/load-test")
@RequiredArgsConstructor
public class LoadTestController {

    private final LoadTestRunnerService loadTestRunnerService;
    private final RunAllToggleService runAllToggleService;
    private final LoadTestProperties defaults;

    @PostMapping("/run")
    public ResponseEntity<LoadTestResult> runLoadTest(@RequestBody(required = false) @Valid LoadTestRequest request) {
        String algorithm = request != null && request.getAlgorithm() != null
                ? request.getAlgorithm()
                : defaults.getAlgorithm();

        int iterations = request != null && request.getIterations() != null
                ? request.getIterations()
                : defaults.getIterations();

        return ResponseEntity.ok(loadTestRunnerService.runLoadTest(algorithm, iterations));
    }

    @GetMapping("/defaults")
    public Map<String, Object> defaults() {
        return Map.of(
                "algorithm", defaults.getAlgorithm(),
                "iterations", defaults.getIterations()
        );
    }

    @PostMapping("/run-all")
    public ResponseEntity<String> runAllBenchmarks(@RequestParam(defaultValue = "2000") int iterations) {
        boolean started = runAllToggleService.toggle(iterations);
        if (started) {
            return ResponseEntity.ok("Auto run-all enabled: 5s pause between cycles with " + iterations
                    + " iterations per algorithm. Call /load-test/run-all again to stop.");
        }
        return ResponseEntity.ok("Auto run-all disabled.");
    }
}
