package com.binaryscan.cchecker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.binaryscan.cchecker.service.CheckerLimits;

@SpringBootApplication
@EnableConfigurationProperties(CheckerLimits.class)
public class CCheckerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CCheckerApplication.class, args);
    }
}
