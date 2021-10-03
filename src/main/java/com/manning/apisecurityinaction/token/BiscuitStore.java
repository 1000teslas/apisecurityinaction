package com.manning.apisecurityinaction.token;

import java.security.SecureRandom;
import java.util.Optional;

import com.clevercloud.biscuit.crypto.KeyPair;

import spark.Request;

public class BiscuitStore<T> implements SecureTokenStore<T> {
    // private final TokenStore<T> delegate;
    // private final KeyPair root;
    // private final SecureRandom rng;

    @Override
    public String create(Request request, T token) {
        return "";
    }

    @Override
    public Optional<T> read(Request request, String tokenId) {
        return Optional.empty();
    }

    @Override
    public void revoke(Request request, String tokenId) {
    }
}
