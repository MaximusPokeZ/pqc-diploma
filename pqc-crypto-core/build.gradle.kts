plugins {
    `java-library`
}

description = "Post-quantum cryptography core library (ML-DSA, ML-KEM, hybrid crypto)"

dependencies {

    // ZStandard JNI wrapper
    implementation("com.github.luben:zstd-jni:1.5.7-7")

    // LZ4 Java
    implementation("at.yawk.lz4:lz4-java:1.10.4")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.assertj:assertj-core:3.27.7")
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf(
        "--enable-preview"
    ))
}

tasks.withType<Test> {
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    jvmArgs("--enable-preview")
}

tasks.withType<Javadoc> {
    (options as StandardJavadocDocletOptions).apply {
        addBooleanOption("-enable-preview", true)
        addStringOption("source", "25")
    }
}
