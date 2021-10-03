package com.manning.apisecurityinaction.token;

public interface SecureTokenStore<T> extends ConfidentialTokenStore<T>, AuthenticatedTokenStore<T> {

}
