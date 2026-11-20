package org.example;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.example.service.*;
import org.example.repository.UserSessionRepository;
import org.example.model.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import java.net.*;
import java.net.http.*;
import java.util.*;
import java.util.concurrent.*;
import tools.jackson.databind.json.JsonMapper;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
 "spring.datasource.url=${TEST_DB_URL:jdbc:postgresql://localhost:5432/survey_lab5_test}"})
class SecurityTests {
 @Value("${local.server.port}") int port;
 @Autowired JdbcTemplate db;
 @Autowired JwtService jwt;
 @Autowired TokenService tokens;
 @org.springframework.test.context.bean.override.mockito.MockitoSpyBean UserSessionRepository sessions;
 @Autowired PlatformTransactionManager manager;
 final JsonMapper json = JsonMapper.builder().build();
 HttpResponse<String> call(String path, String body, String bearer) throws Exception {
  var r=HttpRequest.newBuilder(URI.create("http://localhost:"+port+path)).header("Content-Type","application/json");
  if(bearer!=null) r.header("Authorization","Bearer "+bearer);
  return HttpClient.newHttpClient().send((body==null?r.GET():r.POST(HttpRequest.BodyPublishers.ofString(body))).build(),HttpResponse.BodyHandlers.ofString());
 }
 String refresh(String token) { return "{\"refreshToken\":\""+token+"\"}"; }
 @Test void httpContractRotationAndReplay() throws Exception {
  var login=call("/auth/login","{\"username\":\"admin\",\"password\":\"TestAdmin123!\",\"deviceId\":\"test\"}",null);
  assertEquals(200,login.statusCode(),login.body());
  var pair=json.readTree(login.body()); String access=pair.path("accessToken").asText(), old=pair.path("refreshToken").asText();
  assertEquals(200,call("/api/auth/me",null,access).statusCode());
  assertEquals(401,call("/api/auth/me",null,old).statusCode());
  assertEquals(401,call("/auth/refresh",refresh(access),null).statusCode());
  var updated=call("/auth/refresh",refresh(old),null); assertEquals(200,updated.statusCode(),updated.body());
  var next=json.readTree(updated.body()); assertNotEquals(access,next.path("accessToken").asText()); assertNotEquals(old,next.path("refreshToken").asText());
  assertEquals("USED",db.queryForObject("select status from user_sessions where refresh_token=?",String.class,old));
  assertEquals(401,call("/auth/refresh",refresh(old),null).statusCode());
  assertEquals("REVOKED",db.queryForObject("select status from user_sessions where refresh_token=?",String.class,old));
  assertEquals("ACTIVE",db.queryForObject("select status from user_sessions where refresh_token=?",String.class,next.path("refreshToken").asText()));
  assertEquals(401,call("/auth/refresh",refresh(old),null).statusCode());
  assertEquals(200,call("/api/auth/me",null,access).statusCode());
  assertEquals(400,call("/auth/refresh","{}",null).statusCode());
  assertEquals(401,call("/auth/login","{\"username\":\"admin\",\"password\":\"wrong\"}",null).statusCode());
 }
 @Test void registrationAndConcurrentRefresh() throws Exception {
  String name="jwt_"+UUID.randomUUID().toString().replace("-","");
  String body="{\"username\":\""+name+"\",\"password\":\"TestAccount123!\",\"role\":\"ADMIN\"}";
  var r=call("/auth/register",body,null); assertEquals(201,r.statusCode(),r.body());
  assertEquals("USER",db.queryForObject("select role from app_users where username=?",String.class,name));
  assertEquals(409,call("/auth/register",body,null).statusCode());
  String token=json.readTree(r.body()).path("refreshToken").asText();
  var gate=new CountDownLatch(1); var pool=Executors.newFixedThreadPool(2);
  try {
   Callable<Integer> task=()->{gate.await(); return call("/auth/refresh",refresh(token),null).statusCode();};
   var a=pool.submit(task); var b=pool.submit(task); gate.countDown();
   assertEquals(Set.of(200,401),Set.of(a.get(20,TimeUnit.SECONDS),b.get(20,TimeUnit.SECONDS)));
   assertEquals(2,db.queryForObject("select count(*) from user_sessions where username=?",Integer.class,name));
   assertEquals("REVOKED",db.queryForObject("select status from user_sessions where refresh_token=?",String.class,token));
  } finally {pool.shutdownNow();}
 }
 @Test void failedSaveRollsBackRegistrationAndRotation() {
  String name="rb_"+UUID.randomUUID().toString().replace("-","");
  User user=new User(); user.setUsername(name); user.setPassword("TestAccount123!");
  assertThrows(RuntimeException.class,()->tokens.register(user,"x".repeat(256)));
  assertEquals(0,db.queryForObject("select count(*) from app_users where username=?",Integer.class,name));
  var pair=tokens.login("admin","TestAdmin123!","rollback");
  new TransactionTemplate(manager).executeWithoutResult(s-> sessions.findForUpdate(pair.refreshToken()).orElseThrow().setStatus(SessionStatus.REVOKED));
  assertThrows(org.springframework.security.core.AuthenticationException.class,()->tokens.refresh(pair.refreshToken()));
 }
 @Test void failedRotationPreservesActiveSession() throws Exception {
  String name="rotate_"+UUID.randomUUID().toString().replace("-","");
  User user=new User(); user.setUsername(name); user.setPassword("TestAccount123!");
  var pair=tokens.register(user,"ok");
  org.mockito.Mockito.doThrow(new org.springframework.dao.DataIntegrityViolationException("test save failure"))
   .when(sessions).saveAndFlush(org.mockito.ArgumentMatchers.any(UserSession.class));
  try {
   assertThrows(RuntimeException.class,()->tokens.refresh(pair.refreshToken()));
   assertEquals("ACTIVE",db.queryForObject("select status from user_sessions where refresh_token=?",String.class,pair.refreshToken()));
  } finally { org.mockito.Mockito.reset(sessions); }
 }
 @Test void jwtSignatureExpiryAndType() throws Exception {
  var token=jwt.createAccess("admin"); assertEquals("admin",jwt.verifyAccess(token.value()).subject());
  assertThrows(org.springframework.security.core.AuthenticationException.class,()->jwt.verifyRefresh(token.value()));
  assertThrows(org.springframework.security.core.AuthenticationException.class,()->jwt.verifyAccess(token.value()+"x"));
  var expired=new JwtService("a".repeat(32),1,1).createAccess("admin"); Thread.sleep(1100);
  assertThrows(org.springframework.security.core.AuthenticationException.class,()->new JwtService("a".repeat(32),1,1).verifyAccess(expired.value()));
 }
}


