package org.example.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.security.authentication.BadCredentialsException;
import tools.jackson.databind.json.JsonMapper;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

@Service
public class JwtService {
    private final byte[] key;
    private final long accessSeconds, refreshSeconds;
    private final JsonMapper json = JsonMapper.builder().build();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    public record Token(String value, Instant expiry) {}
    public record Claims(String subject, Instant expiry) {}
    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-seconds:900}") long accessSeconds,
                      @Value("${jwt.refresh-seconds:604800}") long refreshSeconds) {
        key = secret.getBytes(StandardCharsets.UTF_8);
        if (key.length < 32 || accessSeconds <= 0 || refreshSeconds <= 0)
            throw new IllegalArgumentException("JWT secret must be at least 32 bytes; lifetimes must be positive");
        this.accessSeconds = accessSeconds; this.refreshSeconds = refreshSeconds;
    }
    public Token createAccess(String username) { return create(username, "access", accessSeconds); }
    public Token createRefresh(String username) { return create(username, "refresh", refreshSeconds); }
    public Claims verifyAccess(String token) { return verify(token, "access"); }
    public Claims verifyRefresh(String token) { return verify(token, "refresh"); }
    private Token create(String username, String type, long seconds) {
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant expiry = now.plusSeconds(seconds);
        String header = encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = encode(json.writeValueAsString(Map.of("sub", username, "type", type,
                "iat", now.getEpochSecond(), "exp", expiry.getEpochSecond(), "jti", UUID.randomUUID().toString())));
        String input = header + "." + payload;
        return new Token(input + "." + encoder.encodeToString(sign(input)), expiry);
    }
    private Claims verify(String token, String type) {
        try {
            if (token == null || token.length() > 8192) throw new IllegalArgumentException();
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) throw new IllegalArgumentException();
            var header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
            if (!"HS256".equals(header.path("alg").asText()) || !"JWT".equals(header.path("typ").asText())
                    || header.has("crit")) throw new IllegalArgumentException();
            if (!MessageDigest.isEqual(sign(parts[0] + "." + parts[1]), Base64.getUrlDecoder().decode(parts[2])))
                throw new IllegalArgumentException();
            var p = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
            if (!p.path("sub").isString() || p.path("sub").asText().isBlank()
                    || !p.path("jti").isString() || p.path("jti").asText().isBlank()
                    || !type.equals(p.path("type").asText()) || !p.path("exp").isIntegralNumber()
                    || !p.path("iat").isIntegralNumber()) throw new IllegalArgumentException();
            long now = Instant.now().getEpochSecond(), expiry = p.path("exp").asLong();
            if (expiry <= now || p.path("iat").asLong() > now || expiry <= p.path("iat").asLong()
                    || (p.has("nbf") && (!p.path("nbf").isIntegralNumber() || p.path("nbf").asLong() > now)))
                throw new IllegalArgumentException();
            return new Claims(p.path("sub").asText(), Instant.ofEpochSecond(expiry));
        } catch (RuntimeException e) { throw new BadCredentialsException("Invalid token"); }
    }
    private String encode(String value) { return encoder.encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
    private byte[] sign(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
}
