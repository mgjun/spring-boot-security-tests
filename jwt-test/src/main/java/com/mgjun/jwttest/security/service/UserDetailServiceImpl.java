package com.mgjun.jwttest.security.service;

import com.mgjun.jwttest.security.entity.User;
import com.mgjun.jwttest.security.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with -> username or email : " + username));
        return UserPrinciple.of(user);
    }

    public UserDetailServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
