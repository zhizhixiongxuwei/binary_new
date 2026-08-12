package com.binaryscan.javachecker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.binaryscan.javachecker.service.CheckerLimits;

@SpringBootApplication
@EnableConfigurationProperties(CheckerLimits.class)
public class JavaCheckerApplication {
    public static void main(String[] args) {
        SpringApplication.run(JavaCheckerApplication.class, args);
    }
}
