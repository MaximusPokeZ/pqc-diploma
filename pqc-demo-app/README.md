# `pqc-demo-app`

Reference Spring Boot application that exercises the `pqc-hybrid` starter end-to-end. The demo signs and verifies JWT-style tokens through `HybridSigner`, exposes REST endpoints for both single-algorithm load tests and cross-scheme comparative benchmarks, and ships Prometheus + Grafana for live observability of latency, signature/token sizes and memory usage.

## What it shows

- **Hybrid signatures in action** – issuing and verifying tokens with `HybridSigner` configured via `application.yml`.
- **Comparative benchmarking** – classical vs. PQC-only vs. hybrid in one click, with metrics tagged by algorithm.
- **Operational visibility** – Micrometer histograms feeding Prometheus, surfaced in a pre-provisioned Grafana dashboard.

## Running

### Local (just the app)

```bash
./gradlew :pqc-demo-app:bootRun
```

App is then on `http://localhost:8080`.

### Full stack (app + Prometheus + Grafana)

```bash
cd pqc-demo-app
./gradlew bootJar
docker compose up
```

| Service | URL | Notes |
| --- | --- | --- |
| Demo app | http://localhost:8080 | REST API |
| Prometheus | http://localhost:9090 | scrapes `/actuator/prometheus` every 5 s |
| Grafana | http://localhost:3000 | login `admin / admin` – dashboard pre-provisioned |

## REST API

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/load-test/run` | Run a benchmark for one algorithm. Body: `{ "algorithm": "...", "iterations": 5000 }` (both optional, defaults from `application.yml`). |
| `GET`  | `/load-test/defaults` | Return the default algorithm and iteration count. |
| `POST` | `/load-test/run-all?iterations=2000` | Toggle a periodic comparative benchmark across all schemes (5 s pause between cycles). Calling again stops it. |
| `GET`  | `/metrics/{algorithm}` | Per-algorithm metric snapshot (timing, sizes, memory, success rate). |
| `GET`  | `/metrics/overhead?baseline=<a>&compared=<b>` | Relative overhead (%) of `b` vs. `a` across all dimensions. |
| `GET`  | `/actuator/prometheus` | Raw Prometheus exposition. |

### Algorithms used by `/load-test/run-all`

The comparative benchmark covers nine schemes:

```
[1] Classical (Ed25519)
[2] Classical (ECDSA_P256)
[3] Classical (RSA_2048)
[4] PQC Only  (ML-DSA-44)
[5] PQC Only  (ML-DSA-65)
[6] PQC Only  (ML-DSA-87)
[7] HYBRID    (Ed25519    + ML-DSA-65)
[8] HYBRID    (ECDSA_P256 + ML-DSA-65)
[9] HYBRID    (RSA_2048   + ML-DSA-65)
```

## Configuration

The app picks up the standard `pqc.*` properties exposed by the starter. Defaults shipped in `src/main/resources/application.yml`:

```yaml
pqc:
  encryption:
    mode: HYBRID
    pqc-algorithm: ML_KEM_512
    classical-algorithm: X25519
    compression:
      enabled: true
      algorithm: ZSTD
  signature:
    enabled: true
    mode: HYBRID
    pqc-algorithm: ML_DSA_65
    classical-algorithm: ED25519

demo:
  load-test:
    defaults:
      algorithm: ML-DSA-65
      iterations: 5000
```

See [`pqc-spring-boot-autoconfigure`](../pqc-spring-boot-autoconfigure/README.md#properties) for a full property reference.

## Metrics

All custom meters are tagged with an `algorithm` tag for cross-scheme comparison.

| Name | Type | Description |
| --- | --- | --- |
| `demo.jwt.sign.duration` | Timer | Token signing latency |
| `demo.jwt.verify.duration` | Timer | Token verification latency |
| `demo.jwt.token.size.bytes` | Distribution | Final encoded token size |
| `demo.jwt.signature.size.bytes` | Distribution | Raw signature size |
| `demo.jwt.token.efficiency.percent` | Distribution | Payload-to-token ratio (lower ⇒ more signature overhead) |
| `demo.jwt.memory.used.bytes` | Distribution | Heap delta around sign / verify |
| `demo.jwt.operations.total` | Counter | Operations counter (success / signature_invalid) |

## Project layout

```
pqc-demo-app/
├── src/main/java/io/mzaslav/pqc/demo/
│   ├── PqcDemoApplication.java
│   ├── config/        # Security, Micrometer, load-test properties
│   ├── controller/    # /load-test, /metrics
│   ├── service/       # JwtService, LoadTestRunnerService, ComparativeBenchmarkService, MetricsSnapshotService
│   ├── model/         # DTOs returned by /metrics
│   └── metrics/       # MetricNames constants
├── src/main/resources/application.yml
├── grafana/           # Datasource + dashboards (auto-provisioned)
├── prometheus.yaml
├── Dockerfile         # eclipse-temurin:25-jdk
└── docker-compose.yml # demo + Prometheus + Grafana
```

## Notes

- The token format is a deliberately simple `base64url(payload).base64url(signature)` rather than full JOSE – existing JOSE libraries do not yet support ML-DSA, and the goal here is to compare the underlying primitives.
- Endpoints under `/load-test/**`, `/metrics/**`, `/auth/**`, and `/actuator/**` are open by default in `SecurityConfig` because the demo is intended for local benchmarking. Tighten this for any non-local deployment.
