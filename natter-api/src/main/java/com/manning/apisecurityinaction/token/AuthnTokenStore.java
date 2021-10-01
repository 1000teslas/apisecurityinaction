package com.manning.apisecurityinaction.token;

import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.dalesbred.Database;
import org.json.JSONObject;

import spark.Request;

import static org.checkerframework.checker.nullness.util.NullnessUtil.castNonNull;

public final class AuthnTokenStore implements ConfidentialTokenStore<AuthnToken> {
    private final Database database;
    private final SecureRandom rng;

    public AuthnTokenStore(Database database, SecureRandom rng) {
        this.database = database;
        this.rng = rng;
        // this can only be guaranteed initialized if there are no subclasses
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(this::deleteExpiredTokens, 10, 10,
                TimeUnit.MINUTES);
    }

    public String create(Request request, AuthnToken token) {
        var tokenId = randomId();
        var attrs = new JSONObject(token.attributes).toString();

        database.updateUnique("INSERT INTO tokens(token_id, user_id, expiry, attributes) VALUES(?, ?, ?, ?);",
                Util.hash(tokenId), token.username, token.expiry, attrs);

        return tokenId;
    }

    public Optional<AuthnToken> read(Request request, String tokenId) {
        return database.findOptional(this::readToken,
                "SELECT user_id, expiry, attributes FROM tokens WHERE token_id = ?;", Util.hash(tokenId));
    }

    private AuthnToken readToken(ResultSet resultSet) throws SQLException {
        var username = castNonNull(resultSet.getString("user_id"), "nonnull by db constraint");
        var expiry = castNonNull(resultSet.getTimestamp("expiry"), "nonnull by db constraint").toInstant();
        var json = new JSONObject(castNonNull(resultSet.getString("attributes"), "nonnull by db constraint"));

        var token = new AuthnToken(expiry, username);
        for (var key : json.keySet()) {
            token.attributes.put(key, json.getString(key));
        }
        return token;
    }

    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM tokens WHERE token_id = ?;", Util.hash(tokenId));
    }

    private String randomId() {
        var bytes = new byte[20];
        rng.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    public void deleteExpiredTokens() {
        database.update("DELETE FROM tokens WHERE expiry < current_timestamp;");
    }
}
