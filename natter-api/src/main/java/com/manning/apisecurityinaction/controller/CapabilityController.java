package com.manning.apisecurityinaction.controller;

import java.net.URI;
import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import com.manning.apisecurityinaction.token.Capability;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import spark.Request;
import spark.Response;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public class CapabilityController {
    private final SecureTokenStore<Capability> tokenStore;

    public CapabilityController(SecureTokenStore<Capability> tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createUri(Request request, String path, String perms, Duration expiryDuration) {
        var token = new Capability(Instant.now().plus(expiryDuration));
        token.attributes.put("path", path);
        token.attributes.put("perms", perms);

        var tokenId = tokenStore.create(request, token);

        var uri = URI.create(request.uri());
        return uri.resolve(MessageFormat.format("{0}?access_token={1}", path, tokenId));
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        if (tokenId == null) {
            return;
        }
        tokenStore.read(request, tokenId).ifPresent(token -> {
            var tokenPath = token.attributes.get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                request.attribute("perms",
                        castNonNull(token.attributes.get("perms"), "nonnull since capabilities must have permissions"));
            }
        });
    }
}
