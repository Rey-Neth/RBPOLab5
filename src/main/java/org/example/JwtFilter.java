package org.example;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.example.service.JwtService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {
    private final JwtService jwt;
    private final UserDetailsService accounts;
    public JwtFilter(JwtService jwt, UserDetailsService accounts) { this.jwt = jwt; this.accounts = accounts; }
    @Override protected boolean shouldNotFilter(HttpServletRequest request) { return request.getServletPath().startsWith("/auth/"); }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null) {
            try {
                if (!header.startsWith("Bearer ")) throw new org.springframework.security.authentication.BadCredentialsException("Bearer required");
                var claims = jwt.verifyAccess(header.substring(7));
                var user = accounts.loadUserByUsername(claims.subject());
                if (!user.isEnabled()) throw new org.springframework.security.authentication.DisabledException("Disabled");
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
            } catch (AuthenticationException e) {
                SecurityContextHolder.clearContext(); response.sendError(401); return;
            }
        }
        chain.doFilter(request, response);
    }
}
