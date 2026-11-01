package fixture;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
@SpringBootApplication
@RestController
public class App {
 public static void main(String[] args) { SpringApplication.run(App.class,args); }
 record Principal(String id,String tenant_id,String role,String plan) {}
 static final Map<String,Principal> principals=Map.of("alice",new Principal("alice","north","user","premium"),"bob",new Principal("bob","south","user","free"),"admin",new Principal("root","north","admin","premium"));
 static final Map<String,Map<String,String>> objects=Map.of("1",Map.of("id","1","owner_id","alice","tenant_id","north","value","fixture secret"),"2",Map.of("id","2","owner_id","bob","tenant_id","south","value","other secret"));
 @GetMapping("/fixtures/campus_records/transcripts/catalogue/current/{item_id}")
 public Map<String,String> campus_records_catalogue_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/catalogue/archive/{item_id}")
 public Map<String,String> campus_records_catalogue_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/drafts/current/{item_id}")
 public Map<String,String> campus_records_drafts_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(!principal.id().equals(obj.get("owner_id"))) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/drafts/archive/{item_id}")
 public Map<String,String> campus_records_drafts_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Deliberate fixture: object authorization check omitted.
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/shared/current/{item_id}")
 public Map<String,String> campus_records_shared_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(!principal.id().equals(obj.get("owner_id")) && !principal.role().equals("admin")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/shared/archive/{item_id}")
 public Map<String,String> campus_records_shared_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Deliberate fixture: object authorization check omitted.
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/workspace/current/{item_id}")
 public Map<String,String> campus_records_workspace_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(!principal.tenant_id().equals(obj.get("tenant_id"))) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/workspace/archive/{item_id}")
 public Map<String,String> campus_records_workspace_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Deliberate fixture: object authorization check omitted.
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/audit/current/{item_id}")
 public Map<String,String> campus_records_audit_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(!principal.role().equals("admin")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/audit/archive/{item_id}")
 public Map<String,String> campus_records_audit_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Deliberate fixture: object authorization check omitted.
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/subscription/current/{item_id}")
 public Map<String,String> campus_records_subscription_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(!principal.plan().equals("premium")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/subscription/archive/{item_id}")
 public Map<String,String> campus_records_subscription_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Deliberate fixture: object authorization check omitted.
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/disputed/current/{item_id}")
 public Map<String,String> campus_records_disputed_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(true) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/disputed/archive/{item_id}")
 public Map<String,String> campus_records_disputed_1(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  if(true) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
}
