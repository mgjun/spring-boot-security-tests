package com.mgjun.jwttest.login;

import com.mgjun.jwttest.login.request.LoginForm;
import com.mgjun.jwttest.login.request.SignUpForm;
import com.mgjun.jwttest.login.response.JwtResponse;
import com.mgjun.jwttest.security.entity.Role;
import com.mgjun.jwttest.security.entity.RoleName;
import com.mgjun.jwttest.security.entity.User;
import com.mgjun.jwttest.security.repository.RoleRepository;
import com.mgjun.jwttest.security.repository.UserRepository;
import com.mgjun.jwttest.security.service.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestController {
    
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginForm) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginForm.getUsername(),
                        loginForm.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        String jwtToken = jwtProvider.generateJwtToken(authenticate);
        return ResponseEntity.ok(new JwtResponse(jwtToken));
    }
    
    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignUpForm signUpForm) {
        User user = new User(signUpForm.getName(),
                signUpForm.getUsername(),
                passwordEncoder.encode(signUpForm.getPassword()),
                signUpForm.getEmail());

        Set<String> strRoles = signUpForm.getRole();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch(role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                    roles.add(adminRole);

                    break;
                case "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                    roles.add(pmRole);

                    break;
                default:
                    Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                    roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body("User registered successfully!");
    }
    
    public AuthRestController(AuthenticationManager authenticationManager, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtProvider jwtProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
    }
}
