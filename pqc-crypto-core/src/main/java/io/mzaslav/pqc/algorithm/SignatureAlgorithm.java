package io.mzaslav.pqc.algorithm;

public enum SignatureAlgorithm {
    ML_DSA("ML-DSA"),
    CLASSICAL("CLASSICAL"),
    HYBRID("CLASSICAL-ML-DSA");

    private final String algorithmName;

    SignatureAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }
}