plugins {
    `java-library`
}

description = "Spring Boot autoconfiguration for post-quantum cryptography"

dependencies {
    api(project(":pqc-crypto-core"))

    implementation("org.springframework.boot:spring-boot-starter")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

}