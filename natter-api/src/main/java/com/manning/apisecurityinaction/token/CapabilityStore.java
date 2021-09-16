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

public final class CapabilityStore implements ConfidentialTokenStore<Capability> {
    private final Database database;
    private final SecureRandom secureRandom;

    public CapabilityStore(Database database) {
        this.database = database;
        this.secureRandom = new SecureRandom();
        // this can only be guaranteed initialized if there are no subclasses
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(this::deleteExpiredTokens, 10, 10,
                TimeUnit.MINUTES);
    }

    public String create(Request request, Capability token) {
        var tokenId = randomId();
        var attrs = new JSONObject(token.attributes).toString();

        database.updateUnique("INSERT INTO caps(cap_id, expiry, attributes) VALUES(?, ?, ?);", Util.hash(tokenId),
                token.expiry, attrs);

        return tokenId;
    }

    public Optional<Capability> read(Request request, String tokenId) {
        return database.findOptional(this::readToken, "SELECT expiry, attributes FROM caps WHERE cap_id = ?;",
                Util.hash(tokenId));
    }

    private Capability readToken(ResultSet resultSet) throws SQLException {
        var expiry = castNonNull(resultSet.getTimestamp("expiry"), "nonnull by db constraint").toInstant();
        var json = new JSONObject(castNonNull(resultSet.getString("attributes"), "nonnull by db constraint"));

        var token = new Capability(expiry);
        for (var key : json.keySet()) {
            token.attributes.put(key, json.getString(key));
        }
        return token;
    }

    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM caps WHERE cap_id = ?;", Util.hash(tokenId));
    }

    private String randomId() {
        var bytes = new byte[20];
        secureRandom.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    public void deleteExpiredTokens() {
        database.update("DELETE FROM caps WHERE expiry < current_timestamp;");
    }
}
