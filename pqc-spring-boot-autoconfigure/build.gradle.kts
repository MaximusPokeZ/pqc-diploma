plugins {
    `java-library`
}

description = "Spring Boot autoconfiguration for post-quantum cryptography"

dependencies {
    api(project(":pqc-crypto-core"))

    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.assertj:assertj-core:3.27.7")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

}