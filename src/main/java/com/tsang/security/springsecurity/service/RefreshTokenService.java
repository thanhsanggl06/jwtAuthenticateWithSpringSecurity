package com.tsang.security.springsecurity.service;

import com.tsang.security.springsecurity.entity.RefreshToken;
import com.tsang.security.springsecurity.repository.RefreshTokenRepository;
import com.tsang.security.springsecurity.repository.UserInfoRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
public class RefreshTokenService {
    private UserInfoRepository userInfoRepository;
    private RefreshTokenRepository refreshTokenRepository;

    public RefreshToken createRefreshToken(String username){
        RefreshToken refreshToken = RefreshToken.builder()
                .userInfo(userInfoRepository.findByName(username).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(1000*60*10)).build();
        //Chua toi uu
//        Optional<RefreshToken> byUserId = refreshTokenRepository.findByUserId(refreshToken.getUserInfo().getId());
//        if(byUserId.isPresent()){
//            refreshTokenRepository.delete(byUserId.get());
//        }

        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token){
        if(token.getExpiryDate().compareTo(Instant.now())<0){ // Neu token da het han
            refreshTokenRepository.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token was expired. Please make a new signin request");
        }
        return token;
    }
}
