package com.spring.dozen.gateway.infra;

import com.spring.dozen.gateway.application.AuthService;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

// 인증 서비스 호출 클라이언트가 응용 계층의 인터페이스인 AuthService 를 상속받아 DIP 를 적용합니다.
@FeignClient(name = "auth-service")
public interface AuthClient extends AuthService {
    @GetMapping("/api/auth/verify/{userId}")
        // 유저 검증 API
    Boolean verifyUser(@PathVariable("userId") Long userId);
}
