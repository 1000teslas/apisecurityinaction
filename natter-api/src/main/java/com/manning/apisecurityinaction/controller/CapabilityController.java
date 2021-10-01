package com.manning.apisecurityinaction.controller;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.EnumSet;

import com.manning.apisecurityinaction.token.Capability;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import org.checkerframework.checker.nullness.qual.Nullable;

import spark.Filter;
import spark.Request;
import spark.Response;

import static spark.Spark.halt;
import static java.text.MessageFormat.format;

public record CapabilityController(SecureTokenStore<Capability> tokenStore) {
    public URI createUri(Request request, String path, EnumSet<Permission> perms, @Nullable Duration expiryDuration) {
        var token = new Capability(expiryDuration == null ? null : Instant.now().plus(expiryDuration), path, perms);

        var tokenId = tokenStore.create(request, token);

        var uri = URI.create(request.uri());
        return uri.resolve(format("{0}?access_token={1}", path, tokenId));
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        if (tokenId == null) {
            return;
        }
        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (Objects.equals(token.path(), request.pathInfo())) {
                request.attribute("perms", token.perms());
            }
        });
    }

    public Filter requirePermission(String method, EnumSet<Permission> permsNeeded) {
        return (request, response) -> {
            if (!method.equalsIgnoreCase(request.requestMethod())) {
                return;
            }
            EnumSet<Permission> permsHad = request.attribute("perms");
            if (permsHad == null || !permsHad.containsAll(permsNeeded)) {
                halt(403);
            }
        };
    }
}
