plugins {
    `java-library`
}

description = "Post-quantum cryptography core library (ML-DSA, ML-KEM, hybrid crypto)"

dependencies {
    // No external dependencies - pure Java 25 implementation
    // Uses native JEP 496 (ML-KEM) and JEP 497 (ML-DSA)
    
    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.26.0")
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf(
        "--enable-preview"
    ))
}

tasks.withType<Test> {
    jvmArgs("--enable-preview")
}

tasks.withType<Javadoc> {
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("-enable-preview", true)
        addStringOption("source", "25")
    }
}
