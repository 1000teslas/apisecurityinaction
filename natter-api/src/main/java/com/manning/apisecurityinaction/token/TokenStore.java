package com.manning.apisecurityinaction.token;

import java.util.*;

import spark.Request;

public interface TokenStore<T> {
    String create(Request request, T token);

    Optional<T> read(Request request, String tokenId);

    void revoke(Request request, String tokenId);
}
