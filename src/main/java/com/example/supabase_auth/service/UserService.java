package com.example.supabase_auth.service;
import com.example.supabase_auth.entity.AppUser;
import com.example.supabase_auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public AppUser registerUser(AppUser user) {
        return userRepository.save(user);
    }
}
