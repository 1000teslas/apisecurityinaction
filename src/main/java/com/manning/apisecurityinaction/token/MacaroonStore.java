package com.manning.apisecurityinaction.token;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import com.github.nitram509.jmacaroons.GeneralCaveatVerifier;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import com.github.nitram509.jmacaroons.MacaroonsVerifier;
import com.github.nitram509.jmacaroons.verifier.TimestampCaveatVerifier;

import spark.Request;

public record MacaroonStore<T> (ConfidentialTokenStore<T> delegate, Key macKey) implements SecureTokenStore<T> {

    @Override
    public String create(Request request, T token) {
        var identifier = delegate.create(request, token);
        var macaroon = MacaroonsBuilder.create("", macKey.getEncoded(), identifier);
        return macaroon.serialize();
    }

    @Override
    public Optional<T> read(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);

        var verifier = new MacaroonsVerifier(macaroon).satisfyGeneral(new TimestampCaveatVerifier())
                .satisfyExact("method = " + request.requestMethod()).satisfyGeneral(new SinceVerifier(request));

        if (verifier.isValid(macKey.getEncoded())) {
            return delegate.read(request, macaroon.identifier);
        }
        return Optional.empty();
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var macaroon = MacaroonsBuilder.deserialize(tokenId);
        delegate.revoke(request, macaroon.identifier);
    }

    private static record SinceVerifier(Request request) implements GeneralCaveatVerifier {
        @Override
        public boolean verifyCaveat(String caveat) {
            if (caveat.startsWith("since > ")) {
                var minSince = Instant.parse(caveat.substring(8));
                var reqSince = Instant.now().minus(1, ChronoUnit.DAYS);
                if (request.queryParams("since") != null) {
                    reqSince = Instant.parse(request.queryParams("since"));
                }
                return reqSince.isAfter(minSince);
            }
            return false;
        }
    }
}
