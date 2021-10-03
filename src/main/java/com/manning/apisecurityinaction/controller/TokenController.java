package com.manning.apisecurityinaction.controller;

import com.manning.apisecurityinaction.token.AuthnToken;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import org.json.JSONObject;

import spark.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;
import static spark.Spark.halt;

public record TokenController(SecureTokenStore<AuthnToken> tokenStore) {
    public JSONObject login(Request request, Response response) {
        String subject = castNonNull(request.attribute("subject"), "nonnull since authenticated");
        var expiry = Instant.now().plus(10, ChronoUnit.MINUTES);

        var token = new AuthnToken(expiry, subject);
        var tokenId = tokenStore.create(request, token);

        response.status(201);
        return new JSONObject().put("token", tokenId);
    }

    public void validateToken(Request request, Response response) throws Exception {
        var tokenId = request.headers("Authorization");
        if (tokenId == null || !tokenId.startsWith("Bearer ")) {
            return;
        }
        tokenId = tokenId.substring(7);
        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (Instant.now().isBefore(token.expiry)) {
                request.attribute("subject", token.username);
                token.attributes.forEach(request::attribute);
            } else {
                response.header("WWW-Authenticate", "Bearer error=\"invalid_token\",error_description=\"Expired\"");
                halt(401);
            }
        });
    }

    public JSONObject logout(Request request, Response response) {
        var tokenId = request.headers("Authorization");
        if (tokenId == null || !tokenId.startsWith("Bearer ")) {
            throw new IllegalArgumentException("missing token header");
        }
        tokenId = tokenId.substring(7);

        tokenStore.revoke(request, tokenId);

        response.status(200);
        return new JSONObject();
    }
}
