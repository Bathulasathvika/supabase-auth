package com.example.supabase_auth.service;

import com.example.supabase_auth.entity.UploadedFile;
import com.example.supabase_auth.repository.UploadedFileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;

@Service
public class FileUploadService {

    @Autowired
    private BackblazeUploader backblazeUploader;

    @Autowired
    private UploadedFileRepository uploadedFileRepository;

    public String uploadFile(MultipartFile file) throws IOException {
        String fileUrl = backblazeUploader.upload(file);

        UploadedFile uploadedFile = new UploadedFile();
        uploadedFile.setFileName(file.getOriginalFilename());
        uploadedFile.setFileUrl(fileUrl);
        uploadedFile.setFileType(file.getContentType());
        uploadedFile.setTranscriptGenerated(false);
        uploadedFile.setUploadedAt(LocalDateTime.now());

        uploadedFileRepository.save(uploadedFile);
        return fileUrl;
    }
}





