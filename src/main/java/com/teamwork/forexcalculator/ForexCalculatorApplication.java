package com.teamwork.forexcalculator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ForexCalculatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(ForexCalculatorApplication.class, args);
    }

}
