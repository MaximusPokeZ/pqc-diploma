package io.mzaslav.pqc.demo.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "demo.load-test.defaults")
public class LoadTestProperties {
    private String algorithm = "ML-DSA-65";
    private int iterations = 5000;
}
