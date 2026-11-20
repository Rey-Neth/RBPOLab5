package org.example.controller;
import org.example.model.User;
import org.example.service.TokenService;
import org.springframework.web.bind.annotation.*;
import static org.springframework.http.HttpStatus.CREATED;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final TokenService tokens;
    public AuthController(TokenService tokens) { this.tokens = tokens; }
    public record Login(String username, String password, String deviceId) {}
    public record Registration(String username, String password, String email, String deviceId) {}
    public record Refresh(String refreshToken) {}
    @PostMapping("/login")
    public TokenService.Pair login(@RequestBody Login body) {
        return tokens.login(body.username(), body.password(), body.deviceId());
    }
    @PostMapping("/register") @ResponseStatus(CREATED)
    public TokenService.Pair register(@RequestBody Registration body) {
        User user = new User(); user.setUsername(body.username()); user.setPassword(body.password()); user.setEmail(body.email());
        return tokens.register(user, body.deviceId());
    }
    @PostMapping("/refresh")
    public TokenService.Pair refresh(@RequestBody Refresh body) {
        return tokens.refresh(body.refreshToken());
    }
}
