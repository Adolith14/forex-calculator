package com.teamwork.forexcalculator.user.securities.springSecurityConfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
public class AsyncConfig {

    @Bean(name = "taskExecutor")
    public Executor taskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);     // Minimum threads
        executor.setMaxPoolSize(10);     // Maximum threads
        executor.setQueueCapacity(100);  // Queue capacity
        executor.setThreadNamePrefix("Async-");
        executor.initialize();
        return executor;
    }
}