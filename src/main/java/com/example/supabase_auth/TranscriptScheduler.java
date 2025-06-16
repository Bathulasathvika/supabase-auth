package com.example.supabase_auth;

import com.example.supabase_auth.entity.UploadedFile;
import com.example.supabase_auth.repository.UploadedFileRepository;
import com.example.supabase_auth.service.TranscriptService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class TranscriptScheduler {

    @Autowired
    private UploadedFileRepository uploadedFileRepository;

    @Autowired
    private TranscriptService transcriptService;

    @Scheduled(fixedRate = 60000) // every 1 min
    public void checkAndGenerateTranscripts() {
        List<UploadedFile> unprocessedFiles = uploadedFileRepository.findByTranscriptGeneratedFalse();

        for (UploadedFile file : unprocessedFiles) {
            String transcript = transcriptService.generateTranscripts(file.getFileUrl(), file.getFileType());
            if (transcript != null) {
                file.setTranscriptGenerated(true);
                uploadedFileRepository.save(file);
                System.out.println("Transcript generated for: " + file.getFileName());
            }
        }
    }
}

