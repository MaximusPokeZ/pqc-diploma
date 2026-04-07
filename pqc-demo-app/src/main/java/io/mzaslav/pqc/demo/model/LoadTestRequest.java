package io.mzaslav.pqc.demo.model;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoadTestRequest {
    private String algorithm;

    @Min(1)
    private Integer iterations;
}
