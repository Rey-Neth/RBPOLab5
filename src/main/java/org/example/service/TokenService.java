package org.example.service;

import org.example.model.*;
import org.example.repository.*;
import org.example.exception.BadRequestException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.time.Instant;
import java.util.Locale;

@Service
public class TokenService {
    private final UserRepository users;
    private final UserService accounts;
    private final UserSessionRepository sessions;
    private final JwtService jwt;
    private final PasswordEncoder encoder;
    public record Pair(String accessToken, String refreshToken) {}
    public TokenService(UserRepository users, UserService accounts, UserSessionRepository sessions,
                        JwtService jwt, PasswordEncoder encoder) {
        this.users = users;
        this.accounts = accounts;
        this.sessions = sessions;
        this.jwt = jwt;
        this.encoder = encoder;
    }
    private static void required(String value) {
        if (value == null || value.isBlank()) throw new BadRequestException("Обязательное поле пусто");
    }
    @Transactional
    public Pair login(String username, String password, String deviceId) {
        required(username); required(password);
        User user = users.findByUsername(username.toLowerCase(Locale.ROOT)).orElseThrow(TokenService::denied);
        if (!Boolean.TRUE.equals(user.getEnabled()) || !encoder.matches(password, user.getPasswordHash())) throw denied();
        return issue(user.getUsername(), deviceId);
    }
    @Transactional
    public Pair register(User user, String deviceId) {
        required(user.getUsername()); required(user.getPassword());
        return issue(accounts.register(user).getUsername(), deviceId);
    }
    // Отказ в доступе сохраняет REVOKED. Ошибки БД откатывают всю операцию.
    @Transactional(noRollbackFor = BadCredentialsException.class)
    public Pair refresh(String token) {
        required(token);
        var claims = jwt.verifyRefresh(token);
        var session = sessions.findForUpdate(token).orElseThrow(TokenService::denied);
        if (!session.getUsername().equals(claims.subject())) throw denied();
        var user = users.findByUsername(session.getUsername()).orElseThrow(TokenService::denied);
        if (!Boolean.TRUE.equals(user.getEnabled()) || !session.getRefreshTokenExpiry().isAfter(Instant.now())) throw denied();
        if (session.getStatus() == SessionStatus.USED) {
            session.setStatus(SessionStatus.REVOKED);
            sessions.flush();
            throw denied();
        }
        if (session.getStatus() != SessionStatus.ACTIVE) throw denied();
        session.setStatus(SessionStatus.USED);
        return issue(session.getUsername(), session.getDeviceId());
    }
    private Pair issue(String username, String deviceId) {
        var access = jwt.createAccess(username);
        var refresh = jwt.createRefresh(username);
        sessions.saveAndFlush(new UserSession(username, deviceId, access.value(), refresh.value(), access.expiry(), refresh.expiry()));
        return new Pair(access.value(), refresh.value());
    }
    private static BadCredentialsException denied() { return new BadCredentialsException("Authentication failed"); }
}
