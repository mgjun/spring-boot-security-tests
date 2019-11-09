package com.mgjun.jwttest.security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class JwtAuthTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private UserDetailServiceImpl userDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwt(httpServletRequest);
            Optional.ofNullable(jwt)
                    .filter(jwtToken -> jwtProvider.validateJwtToken(jwtToken))
                    .ifPresent(jwtToken -> {
                        String username = jwtProvider.getUsernameFromJwtToken(jwtToken);
                        
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                        UsernamePasswordAuthenticationToken securityToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        securityToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

                        SecurityContextHolder.getContext().setAuthentication(securityToken);
                    });
        } catch (Exception e) {
            logger.error("Can NOT set user authentication -> Message: ", e);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private String getJwt(HttpServletRequest request) {
        String authentication = request.getHeader("Authorization");
        return Optional.ofNullable(authentication)
                .filter(auth -> auth.startsWith("Bearer "))
                .map(auth -> auth.replace("Bearer ", ""))
                .orElse(null);
    }
}
