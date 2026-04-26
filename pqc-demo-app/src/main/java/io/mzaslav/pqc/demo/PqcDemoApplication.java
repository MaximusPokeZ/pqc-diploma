package io.mzaslav.pqc.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot entry point for the PQC demo application.
 * <p>
 * The demo wires up the {@code pqc-hybrid-spring-boot-starter}, exposes
 * REST endpoints for benchmarking signature schemes, and ships
 * Prometheus/Grafana dashboards via Micrometer.
 *
 * @author mzaslav
 * @since 1.0
 */
@SpringBootApplication
public class PqcDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(PqcDemoApplication.class, args);
    }
}
