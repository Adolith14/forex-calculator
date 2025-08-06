package com.teamwork.forexcalculator.user.service.s3Service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
public class S3Service {

    private final S3Client s3Client;

    @Value("${aws.s3.bucketName}")
    private String bucketName;

    // Synchronous upload (keep this if needed)
    public String uploadFile(MultipartFile file) throws IOException {
        String key = "avatars/" + UUID.randomUUID() + "_" + file.getOriginalFilename();
        uploadToS3(file, key);
        return generateS3Url(key);
    }

    // Async version
    @Async("taskExecutor")  // Uses the configured thread pool
    public CompletableFuture<String> uploadFileAsync(MultipartFile file) {
        try {
            String key = "avatars/" + UUID.randomUUID() + "_" + file.getOriginalFilename();
            uploadToS3(file, key);
            return CompletableFuture.completedFuture(generateS3Url(key));
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    private void uploadToS3(MultipartFile file, String key) throws IOException {
        PutObjectRequest request = PutObjectRequest.builder()
                .bucket(bucketName)
                .key(key)
                .contentType(file.getContentType())
                .build();
        s3Client.putObject(request, RequestBody.fromBytes(file.getBytes()));
    }

    private String generateS3Url(String key) {
        return "https://" + bucketName + ".s3.amazonaws.com/" + key;
    }
}