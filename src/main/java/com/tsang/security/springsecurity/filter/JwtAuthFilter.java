package com.tsang.security.springsecurity.filter;

import com.tsang.security.springsecurity.config.UserInfoUserDetailsService;
import com.tsang.security.springsecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@NoArgsConstructor
//Dung de xac thuc va uy quyen nguoi dung thong qua jwt
public class JwtAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserInfoUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization"); // Lay gia tri cua header"Authorization" tu request
        String token = null;
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) { //Kiem tra xem header"Authorization" co hop le hay k
            token = authHeader.substring(7); // Lay token bo qua 7 ky tu dau tien
            username = jwtService.extractUsername(token); // trich xuat username tu jwt
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) { // neu ten nguoi dung hop le va chua co thong tin xac thuc trong SecurityContextHolder
            UserDetails userDetails = userDetailsService.loadUserByUsername(username); // lay ra user tu usernamme
            if (jwtService.validateToken(token, userDetails)) { //kiem tra tinh hop le cua jwt
                //Tao doi tuong xac thuc cho nguoi dung
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); //set thong tin chi tiet xac thuc
                SecurityContextHolder.getContext().setAuthentication(authToken); //set thong tin xac thuc vao securityContextHolder
            }
        }
        filterChain.doFilter(request, response);
    }
}
