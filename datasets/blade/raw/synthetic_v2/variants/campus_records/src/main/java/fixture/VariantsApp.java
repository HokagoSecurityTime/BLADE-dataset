package fixture;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
@SpringBootApplication
@RestController
public class VariantsApp {
 public static void main(String[] args) { SpringApplication.run(VariantsApp.class,args); }
 record Principal(String id,String tenant_id,String role,String plan) {}
 static final Map<String,Principal> principals=Map.of("alice",new Principal("alice","north","user","premium"),"bob",new Principal("bob","south","user","free"),"admin",new Principal("root","north","admin","premium"));
 static final Map<String,Map<String,String>> objects=Map.of("1",Map.of("id","1","owner_id","alice","tenant_id","north","value","fixture secret"),"2",Map.of("id","2","owner_id","bob","tenant_id","south","value","other secret"));
 // Security config (not shown) maps Bearer tokens to Principal; @PreAuthorize("isAuthenticated()") enforces authentication only.
 @GetMapping("/fixtures/campus_records/transcripts/drafts/authonly/{item_id}")
 public Map<String,String> campus_records_drafts_authonly(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Variant: object authorization check removed.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/drafts/extauth/{item_id}")
 public Map<String,String> campus_records_drafts_extauth(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  // Variant: authentication by @PreAuthorize only; no authorization check.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/drafts/extguard/{item_id}")
 public Map<String,String> campus_records_drafts_extguard(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  if(!principal.id().equals(obj.get("owner_id"))) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/shared/authonly/{item_id}")
 public Map<String,String> campus_records_shared_authonly(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Variant: object authorization check removed.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/shared/extauth/{item_id}")
 public Map<String,String> campus_records_shared_extauth(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  // Variant: authentication by @PreAuthorize only; no authorization check.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/shared/extguard/{item_id}")
 public Map<String,String> campus_records_shared_extguard(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  if(!principal.id().equals(obj.get("owner_id")) && !principal.role().equals("admin")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/workspace/authonly/{item_id}")
 public Map<String,String> campus_records_workspace_authonly(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Variant: object authorization check removed.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/workspace/extauth/{item_id}")
 public Map<String,String> campus_records_workspace_extauth(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  // Variant: authentication by @PreAuthorize only; no authorization check.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/workspace/extguard/{item_id}")
 public Map<String,String> campus_records_workspace_extguard(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  if(!principal.tenant_id().equals(obj.get("tenant_id"))) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
 @GetMapping("/fixtures/campus_records/transcripts/audit/authonly/{item_id}")
 public Map<String,String> campus_records_audit_authonly(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));
  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
  // Variant: object authorization check removed.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/audit/extauth/{item_id}")
 public Map<String,String> campus_records_audit_extauth(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  // Variant: authentication by @PreAuthorize only; no authorization check.
  return obj;
 }
 @PreAuthorize("isAuthenticated()")
 @GetMapping("/fixtures/campus_records/transcripts/audit/extguard/{item_id}")
 public Map<String,String> campus_records_audit_extguard(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {
  var obj=objects.get(item_id);
  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  if(!principal.role().equals("admin")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
  return obj;
 }
}
