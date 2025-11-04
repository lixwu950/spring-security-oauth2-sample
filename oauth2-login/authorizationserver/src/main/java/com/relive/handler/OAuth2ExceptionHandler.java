package com.relive.handler;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class OAuth2ExceptionHandler {

    @ExceptionHandler(OAuth2AuthorizationCodeRequestAuthenticationException.class)
    public ResponseEntity<Object> handleOAuth2Exception(OAuth2AuthorizationCodeRequestAuthenticationException ex) {
        // 记录详细的错误信息
        System.out.println("OAuth2 Error: " + ex.getError());
        System.out.println("Error Description: " + ex.getAuthorizationCodeRequestAuthentication().getAuthorizationUri());

        // 返回错误信息以便调试
        Map<String, String> errorResponse = new HashMap<>();
        errorResponse.put("error", ex.getError().getErrorCode());
        errorResponse.put("error_description", ex.getError().getDescription());

        return ResponseEntity.badRequest().body(errorResponse);
    }
}