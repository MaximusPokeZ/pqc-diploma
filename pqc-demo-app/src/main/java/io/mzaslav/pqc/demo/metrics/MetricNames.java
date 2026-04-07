package io.mzaslav.pqc.demo.metrics;

public final class MetricNames {
    public static final String SIGN_DURATION = "demo.jwt.sign.duration";
    public static final String VERIFY_DURATION = "demo.jwt.verify.duration";
    public static final String TOKEN_SIZE_BYTES = "demo.jwt.token.size.bytes";
    public static final String SIGNATURE_SIZE_BYTES = "demo.jwt.signature.size.bytes";
    public static final String TOKEN_EFFICIENCY_PERCENT = "demo.jwt.token.efficiency.percent";
    public static final String MEMORY_USED_BYTES = "demo.jwt.memory.used.bytes";
    public static final String OPERATIONS_TOTAL = "demo.jwt.operations.total";

    private MetricNames() {
    }
}
