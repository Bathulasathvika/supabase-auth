package com.example.supabase_auth;



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.S3Utilities;

import java.net.URI;

@Configuration
public class BackblazeConfig {

    @Bean
    public S3Client s3Client() {
        return S3Client.builder()
                .endpointOverride(URI.create("https://s3.us-east-005.backblazeb2.com")) // replace <region>
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create("005de482a32e09e0000000001", "K005Vzr/e/ZejuLSWac8TUrlQuq47xA")))
                .region(Region.of("us-east-005")) // Use your actual Backblaze B2 region string
                // Backblaze region
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build();
    }
}

