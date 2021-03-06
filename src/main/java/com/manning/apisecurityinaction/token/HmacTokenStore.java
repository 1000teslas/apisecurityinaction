package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.Mac;

import spark.Request;

public class HmacTokenStore<T> implements SecureTokenStore<T> {
    private final TokenStore<T> delegate;
    private final Key macKey;

    private HmacTokenStore(TokenStore<T> delegate, Key macKey) {
        this.delegate = delegate;
        this.macKey = macKey;
    }

    public static <T> SecureTokenStore<T> wrap(ConfidentialTokenStore<T> store, Key macKey) {
        return new HmacTokenStore<T>(store, macKey);
    }

    public static <T> AuthenticatedTokenStore<T> wrap(TokenStore<T> store, Key macKey) {
        return new HmacTokenStore<T>(store, macKey);
    }

    @Override
    public String create(Request request, T token) {
        var tokenId = delegate.create(request, token);
        var tag = hmac(tokenId);
        return tokenId + '.' + Base64Url.encode(tag);
    }

    private byte[] hmac(String tokenId) {
        try {
            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);
            return mac.doFinal(tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<T> read(Request request, String tokenId) {
        var index = tokenId.lastIndexOf('.');
        if (index == -1) {
            return Optional.empty();
        }
        var realTokenId = tokenId.substring(0, index);
        var provided = Base64Url.decode(tokenId.substring(index + 1));
        var computed = hmac(realTokenId);
        if (!MessageDigest.isEqual(provided, computed)) {
            return Optional.empty();
        }
        return delegate.read(request, realTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var index = tokenId.lastIndexOf('.');
        if (index == -1) {
            return;
        }
        var realTokenId = tokenId.substring(0, index);
        var provided = Base64Url.decode(tokenId.substring(index + 1));
        var computed = hmac(realTokenId);
        if (MessageDigest.isEqual(provided, computed)) {
            delegate.revoke(request, realTokenId);
        }
    }
}
