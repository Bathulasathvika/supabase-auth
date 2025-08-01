package com.example.supabase_auth.service;

import com.example.supabase_auth.entity.UploadedFile;
import com.example.supabase_auth.repository.UploadedFileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TranscriptService {

    @Autowired
    private UploadedFileRepository uploadedFileRepository;

    public String generateTranscripts(String fileUrl, String fileType) {

        return "Sample transcript for file: " + fileUrl;
    }
}


