package com.kb.security.handler;

import com.kb.member.dto.Member;
import com.kb.security.dto.JwtDTO;
import com.kb.security.util.JsonResponse;
import com.kb.security.util.JwtProcessor;
import com.kb.security.util.JwtProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // 인증 결과 Principal
        Member member = (Member) authentication.getPrincipal();
        log.info("Authenticated user: {}", member);
        log.info("Generating JWT...");
        JwtDTO token = jwtProvider.generateToken(member.getUsername());
        log.info("JWT generated: {}", token);
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("id", member.getUsername());
        responseData.put("token", token);
        JsonResponse.send(response, responseData);
    }

}
