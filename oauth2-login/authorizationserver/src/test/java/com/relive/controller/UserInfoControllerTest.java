package com.relive.controller;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Collections;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserInfoController.class)
public class UserInfoControllerTest {

    private MockMvc mockMvc;

    // 模拟 OAuth2 登录相关配置
    @Value("${oauth2.client-id}")
    private String clientId;  // 假设 clientId 来自配置文件

    @Value("${oauth2.client-secret}")
    private String clientSecret;  // 假设 clientSecret 来自配置文件

    @Value("${oauth2.token-uri}")
    private String tokenUri;  // 假设 tokenUri 来自配置文件

    @Value("${oauth2.redirect-uri}")
    private String redirectUri;  // 假设 redirectUri 来自配置文件

    @BeforeEach
    public void setup() {
        // 设置 MockMvc 来模拟控制器
        mockMvc = MockMvcBuilders
                .standaloneSetup(new UserInfoController())  // 初始化 Controller
                .build();
    }

    @Test
    public void testUserInfoWithRealLogin() throws Exception {
        // 第一步：模拟 OAuth2 登录，获取授权码
        // 假设我们已经手动完成了 OAuth2 授权码流程，得到了授权码
        String authorizationCode = "sample-authorization-code";  // 假设授权码来自 URL 参数

        // 第二步：使用授权码请求 token
        mockMvc.perform(MockMvcRequestBuilders.post(tokenUri)
                        .param("grant_type", "authorization_code")
                        .param("code", authorizationCode)  // 从授权码获取的授权码
                        .param("redirect_uri", redirectUri)
                        .param("client_id", clientId)
                        .param("client_secret", clientSecret)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(MockMvcResultMatchers.status().isOk())  // 期望返回 HTTP 200
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").exists())  // 验证返回的 access_token
                .andDo(result -> {
                    // 从响应中获取 access_token
                    String accessToken = result.getResponse().getContentAsString();
                    accessToken = accessToken.replace("\"", "").trim();  // 处理为纯字符串 access_token

                    // 第三步：使用 Access Token 访问受保护的 /userInfo 接口
                    mockMvc.perform(MockMvcRequestBuilders.get("/userInfo")
                                    .header("Authorization", "Bearer " + accessToken))  // 使用 Bearer Token
                            .andExpect(MockMvcResultMatchers.status().isOk())  // 期望 HTTP 200
                            .andExpect(MockMvcResultMatchers.jsonPath("$.data.sub").value("testuser"));  // 验证用户信息的 sub 字段
                });
    }
}