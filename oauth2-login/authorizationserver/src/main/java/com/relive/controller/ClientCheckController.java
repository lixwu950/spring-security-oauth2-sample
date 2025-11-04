package com.relive.controller;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ClientCheckController {

    private final RegisteredClientRepository clientRepository;

    public ClientCheckController(RegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @GetMapping("/check-client")
    public String checkClient() {
        RegisteredClient client = clientRepository.findByClientId("relive-client");
        if (client != null) {
            return "Client found: " + client.getClientId() +
                    ", Redirect URIs: " + client.getRedirectUris() +
                    ", Scopes: " + client.getScopes();
        } else {
            return "Client not found!";
        }
    }

    @GetMapping("/test")
    public String test() {
        return "Server is running!";
    }
}
