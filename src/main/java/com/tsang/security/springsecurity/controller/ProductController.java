package com.tsang.security.springsecurity.controller;

import com.tsang.security.springsecurity.dto.AuthRequest;
import com.tsang.security.springsecurity.dto.JwtResponse;
import com.tsang.security.springsecurity.dto.Product;
import com.tsang.security.springsecurity.dto.RefreshTokenRequest;
import com.tsang.security.springsecurity.entity.RefreshToken;
import com.tsang.security.springsecurity.entity.UserInfo;
import com.tsang.security.springsecurity.service.JwtService;
import com.tsang.security.springsecurity.service.ProductService;
import com.tsang.security.springsecurity.service.RefreshTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/products")
@AllArgsConstructor
public class ProductController {

    private ProductService service;

    private JwtService jwtService;

    private AuthenticationManager authenticationManager;
    private RefreshTokenService refreshTokenService;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<Product> getAllTheProducts() {
        return service.getProducts();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public Product getProductById(@PathVariable int id) {
        return service.getProduct(id);
    }

    @PostMapping("/new")
    public String addUser(@RequestBody UserInfo userInfo){
        return service.addUser(userInfo);
    }

    @PostMapping("/authenticate")
    public JwtResponse authenticateAndGetToken(@RequestBody AuthRequest authRequest){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if(authentication.isAuthenticated()){
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(authRequest.getUsername());
            return JwtResponse.builder().accessToken(jwtService.generateToken(authRequest.getUsername()))
                    .token(refreshToken.getToken()).build();

        }else {
            throw new UsernameNotFoundException("user not found");
        }
    }

    @PostMapping("/refreshToken")
    public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
     return refreshTokenService.findByToken(refreshTokenRequest.getToken())
                .map(token -> refreshTokenService.verifyExpiration(token))
                .map(token -> token.getUserInfo())
                .map(userInfo -> {
                    String accessToken = jwtService.generateToken(userInfo.getName());
                    return JwtResponse.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequest.getToken())
                            .build();
                }).orElseThrow(() -> new RuntimeException(
                        "refresh token is not in database!"
                ));
    }
}
