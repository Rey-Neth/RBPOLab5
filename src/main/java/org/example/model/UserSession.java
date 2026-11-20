package org.example.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_sessions")
public class UserSession {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(nullable = false) private String username;
    private String deviceId;
    @Column(nullable = false, columnDefinition = "text") private String accessToken;
    @Column(nullable = false, unique = true, columnDefinition = "text") private String refreshToken;
    @Column(nullable = false) private Instant accessTokenExpiry;
    @Column(nullable = false) private Instant refreshTokenExpiry;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private SessionStatus status;
    public UserSession() {}
    public UserSession(String username, String deviceId, String accessToken, String refreshToken,
                       Instant accessTokenExpiry, Instant refreshTokenExpiry) {
        this.username = username; this.deviceId = deviceId; this.accessToken = accessToken;
        this.refreshToken = refreshToken; this.accessTokenExpiry = accessTokenExpiry;
        this.refreshTokenExpiry = refreshTokenExpiry; this.status = SessionStatus.ACTIVE;
    }
    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public String getDeviceId() { return deviceId; }
    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public Instant getAccessTokenExpiry() { return accessTokenExpiry; }
    public Instant getRefreshTokenExpiry() { return refreshTokenExpiry; }
    public SessionStatus getStatus() { return status; }
    public void setStatus(SessionStatus status) { this.status = status; }
}
