package com.example.supabase_auth.repository;


import com.example.supabase_auth.entity.UploadedFile;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface UploadedFileRepository extends JpaRepository<UploadedFile, Long> {
    List<UploadedFile> findByTranscriptGeneratedFalse();
}
