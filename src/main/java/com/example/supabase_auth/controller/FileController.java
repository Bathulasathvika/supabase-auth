package com.example.supabase_auth.controller;


import com.example.supabase_auth.service.BackBlazeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/files")
public class FileController {
    private final BackBlazeService backblazeService;

    public FileController(BackBlazeService backblazeService) {
        this.backblazeService = backblazeService;
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file) {
        try {
            String fileKey = backblazeService.uploadFile(file);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "fileKey", fileKey,
                    "message", "File uploaded to Backblaze B2"
            ));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Upload failed: " + e.getMessage()
            ));
        }
    }
}