package io.mzaslav.pqc.demo.controller;

import io.mzaslav.pqc.demo.model.AlgorithmMetrics;
import io.mzaslav.pqc.demo.model.OverheadMetrics;
import io.mzaslav.pqc.demo.service.MetricsSnapshotService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller that surfaces aggregated benchmark metrics.
 * <p>
 * Endpoints:
 * <ul>
 *   <li>{@code GET /metrics/{algorithm}} - per-algorithm metric snapshot
 *       (timing, sizes, memory, success rate)</li>
 *   <li>{@code GET /metrics/overhead?baseline=&compared=} - relative overhead
 *       between two algorithms (useful for "PQC vs classical" charts)</li>
 * </ul>
 *
 * @author mzaslav
 * @since 1.0
 */
@RestController
@RequestMapping("/metrics")
@RequiredArgsConstructor
public class MetricsController {

    private final MetricsSnapshotService metricsSnapshotService;

    @GetMapping("/{algorithm}")
    public AlgorithmMetrics byAlgorithm(@PathVariable String algorithm) {
        return metricsSnapshotService.extractMetrics(algorithm);
    }

    @GetMapping("/overhead")
    public OverheadMetrics overhead(
            @RequestParam String baseline,
            @RequestParam String compared
    ) {
        AlgorithmMetrics baselineMetrics = metricsSnapshotService.extractMetrics(baseline);
        AlgorithmMetrics comparedMetrics = metricsSnapshotService.extractMetrics(compared);
        return metricsSnapshotService.calculateOverhead(baselineMetrics, comparedMetrics);
    }
}
