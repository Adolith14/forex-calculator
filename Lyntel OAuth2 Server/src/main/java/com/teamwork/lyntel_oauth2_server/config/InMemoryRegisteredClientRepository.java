package com.teamwork.lyntel_oauth2_server.config;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashMap;
import java.util.Map;

public class InMemoryRegisteredClientRepository implements RegisteredClientRepository {
    private final Map<String, RegisteredClient> clients = new HashMap<>();

    public InMemoryRegisteredClientRepository(RegisteredClient... clients) {
        for (RegisteredClient client : clients) {
            this.clients.put(client.getClientId(), client);
        }
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        clients.put(registeredClient.getClientId(), registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clients.values().stream()
                .filter(client -> client.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clients.get(clientId);
    }
}