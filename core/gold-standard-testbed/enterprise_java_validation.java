public class enterprise_java_validation {
  public void cases() {
    // Vulnerable: CAM-001
    String snippet_0 = """String expr = request.getExpression();
runtimeService.startProcessInstanceByKey("payment", Variables.putValue("approvalExpr", expr));""";
    // Vulnerable: CAM-002
    String snippet_1 = """runtimeService.setVariable(piId, "ssn", req.ssn());
historyService.createHistoricVariableInstanceQuery().list();""";
    // Vulnerable: CAM-003
    String snippet_2 = """RepositoryService repo = processEngine.getRepositoryService();
repo.createDeployment().addInputStream("process.bpmn", userUploadedXml).deploy();""";
    // Vulnerable: CAM-004
    String snippet_3 = """taskService.claim(taskId, currentUser);
taskService.complete(taskId, vars);""";
    // Vulnerable: CAM-005
    String snippet_4 = """executionListener(event="end"){ outboxPublisher.publish("APPROVED", execution.getProcessBusinessKey()); }""";
    // Vulnerable: CAM-006
    String snippet_5 = """serviceTask camunda:asyncBefore="true" """;
    // Vulnerable: CAM-007
    String snippet_6 = """delegate.execute(){ bankApi.debit(...); throw new BpmnError("DECLINED"); }""";
    // Vulnerable: CAM-008
    String snippet_7 = """execution.setVariableLocal("approved", true);""";
    // Vulnerable: CAM-009
    String snippet_8 = """taskListener.create(){ userService.promote(task.getAssignee()); }""";
    // Vulnerable: CAM-010
    String snippet_9 = """compensationDelegate.execute(){ refund(execution.getVariable("amount")); }""";
    // Vulnerable: CAM-011
    String snippet_10 = """runtimeService.signalEventReceived("PaymentApproved");""";
    // Vulnerable: CAM-012
    String snippet_11 = """runtimeService.createMessageCorrelation("InvoicePaid").processInstanceBusinessKey(req.businessKey()).correlate();""";
    // Vulnerable: CAM-013
    String snippet_12 = """serviceTask asyncBefore=true; delegate: gateway.charge();""";
    // Vulnerable: CAM-014
    String snippet_13 = """callActivity calledElement="...";""";
    // Vulnerable: CAM-015
    String snippet_14 = """@Component("riskDelegate") class RiskDelegate implements JavaDelegate { private Map<String,Object> cache = new HashMap<>(); }""";
    // Vulnerable: CAM-016
    String snippet_15 = """camunda:failedJobRetryTimeCycle="R999/PT1S" """;
    // Vulnerable: CAM-017
    String snippet_16 = """@PostMapping("/camunda/task/{id}/complete") taskService.complete(id, vars);""";
    // Vulnerable: CAM-018
    String snippet_17 = """processEngineConfiguration.setAuthorizationEnabled(false); runtimeService.createProcessInstanceQuery().list();""";
    // Vulnerable: CAM-019
    String snippet_18 = """runtimeService.getVariables(procInstId);""";
    // Vulnerable: CAM-020
    String snippet_19 = """runtimeService.createMessageCorrelation("ApprovePayment").processInstanceId(pid).correlate();""";
    // Vulnerable: CAM-021
    String snippet_20 = """@PostMapping("/process/{id}/pdf") byte[] pdf = pdfService.renderFullAudit(id); return ResponseEntity.ok(pdf);""";
    // Vulnerable: CAM-022
    String snippet_21 = """historyService.createHistoricTaskInstanceQuery().list();""";
    // Vulnerable: CAM-023
    String snippet_22 = """runtimeService.startProcessInstanceByKey("bulkImport", vars);""";
    // Vulnerable: CAM-024
    String snippet_23 = """log.info("vars={}", runtimeService.getVariables(piId));""";

    // Vulnerable: SPR-001
    String snippet_24 = """ObjectMapper mapper = new ObjectMapper(); mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL); Object body = mapper.readValue(json, Object.class);""";
    // Vulnerable: SPR-002
    String snippet_25 = """http.csrf(csrf -> csrf.disable()).authorizeHttpRequests(a -> a.requestMatchers("/ui/**").authenticated());""";
    // Vulnerable: SPR-003
    String snippet_26 = """@PatchMapping("/users/{id}") public User update(@PathVariable Long id, @RequestBody Map<String, Object> in) { BeanUtils.populate(userRepo.getReferenceById(id), in); return userRepo.save(...); }""";
    // Vulnerable: SPR-004
    String snippet_27 = """@ExceptionHandler(Exception.class) ResponseEntity<Map<String,String>> e(Exception ex){ return ResponseEntity.status(500).body(Map.of("error", ex.getMessage(), "trace", stackTrace(ex))); }""";
    // Vulnerable: SPR-005
    String snippet_28 = """@GetMapping("/api/orders/{id}") Order o = orderRepo.findById(id).orElseThrow(); return OrderDto.of(o);""";
    // Vulnerable: SPR-006
    String snippet_29 = """@DeleteMapping("/users/{uid}/cards/{cardId}") cardRepo.deleteById(cardId);""";
    // Vulnerable: SPR-007
    String snippet_30 = """@RepositoryRestResource(path="invoices") interface InvoiceRepo extends JpaRepository<Invoice, UUID> {}""";
    // Vulnerable: SPR-008
    String snippet_31 = """@QueryMapping Order order(@Argument UUID id){ return repo.findById(id).orElseThrow(); }""";
    // Vulnerable: SPR-009
    String snippet_32 = """Path p = storage.resolve(request.getParameter("docId")); return Files.readAllBytes(p);""";
    // Vulnerable: SPR-010
    String snippet_33 = """@PostMapping("/accounts/lock") void lock(@RequestBody List<Long> ids){ service.lock(ids); }""";
    // Vulnerable: SPR-011
    String snippet_34 = """@Cacheable("profile") public Profile getProfile(UUID id){ ... }""";
    // Vulnerable: SPR-012
    String snippet_35 = """registry.enableSimpleBroker("/topic");""";
    // Vulnerable: SPR-013
    String snippet_36 = """StringEncryptor e = new PooledPBEStringEncryptor(); e.setAlgorithm("PBEWithMD5AndDES");""";
    // Vulnerable: SPR-014
    String snippet_37 = """byte[] salt = "fixed-salt-prod".getBytes(UTF_8); var spec = new PBEKeySpec(pwd, salt, 10000, 128);""";
    // Vulnerable: SPR-015
    String snippet_38 = """static SecretKey appKey; if(appKey==null) appKey = derive(password);""";
    // Vulnerable: SPR-016
    String snippet_39 = """Unmarshaller u = JAXBContext.newInstance(Model.class).createUnmarshaller(); Model m = (Model) u.unmarshal(inputStream);""";
    // Vulnerable: SPR-017
    String snippet_40 = """Transformer t = TransformerFactory.newInstance().newTransformer(new StreamSource(userXslt)); t.transform(new StreamSource(xml), out);""";
    // Vulnerable: SPR-018
    String snippet_41 = """String user = req.getParameter("user"); String expr = "//account[user/text()='" + user + "']/@role"; xpath.evaluate(expr, doc);""";
    // Vulnerable: SPR-019
    String snippet_42 = """Element assertion = (Element) doc.getElementsByTagName("Assertion").item(0); if (verifySignature(doc)) accept(assertion);""";
    // Vulnerable: SPR-020
    String snippet_43 = """XMLInputFactory xif = XMLInputFactory.newFactory(); XMLStreamReader xsr = xif.createXMLStreamReader(input);""";
    // Vulnerable: SPR-021
    String snippet_44 = """String expr = "hasRole('ADMIN') or " + req.rule(); methodSecurityExpressionHandler.setDefaultRolePrefix("");""";
    // Vulnerable: SPR-022
    String snippet_45 = """@Value("#{...}") private String evaluated;""";
    // Vulnerable: SPR-023
    String snippet_46 = """String route = parser.parseExpression(headers.get("route")).getValue(String.class); jmsTemplate.convertAndSend(route, payload);""";
    // Vulnerable: SPR-024
    String snippet_47 = """mapper.activateDefaultTyping(ptv, DefaultTyping.EVERYTHING); mapper.addMixIn(Object.class, TrustAll.class); Object o = mapper.readValue(json, Object.class);""";
    // Vulnerable: SPR-025
    String snippet_48 = """Yaml yaml = new Yaml(); Object cfg = yaml.load(userYaml);""";
    // Vulnerable: SPR-026
    String snippet_49 = """XStream xs = new XStream(); xs.allowTypesByWildcard(new String[]{"**"}); Object o = xs.fromXML(xml);""";
    // Vulnerable: SPR-027
    String snippet_50 = """Stream.iterate(seed, f).map(this::expand).forEach(this::store);""";
    // Vulnerable: SPR-028
    String snippet_51 = """@Async void run(){ EntityManager em = emf.createEntityManager(); while(true){ em.createQuery("...").getResultList(); } }""";
    // Vulnerable: SPR-029
    String snippet_52 = """@Service class TokenService { private long counter; String next(){ return "T-" + (++counter); } }""";
    // Vulnerable: SPR-030
    String snippet_53 = """if(cache.get(k)==null){ cache.put(k, load(k)); }""";
    // Vulnerable: SPR-031
    String snippet_54 = """public String update(@ModelAttribute User u){ userRepo.save(u); }""";
    // Vulnerable: SPR-032
    String snippet_55 = """binder.setAutoGrowNestedPaths(true);""";
    // Vulnerable: SPR-033
    String snippet_56 = """@PostAuthorize("returnObject.ownerId == authentication.name") public OrderDto get(UUID id){ return mapper.toDto(repo.findById(id).orElseThrow()); }""";
    // Vulnerable: SPR-034
    String snippet_57 = """public boolean hasPermission(Authentication a, Object t, Object p){ return t == null || policy.allow(a, t, p.toString()); }""";
    // Vulnerable: SPR-035
    String snippet_58 = """SignedJWT jwt = SignedJWT.parse(token); JWTClaimsSet c = jwt.getJWTClaimsSet();""";
    // Vulnerable: SPR-036
    String snippet_59 = """JWSVerifier v = new MACVerifier(publicKeyBytes); signedJwt.verify(v);""";
    // Vulnerable: SPR-037
    String snippet_60 = """Jwt jwt = decoder.decode(token); return jwt;""";
    // Vulnerable: SPR-038
    String snippet_61 = """decoder.setJwtValidator(token -> OAuth2TokenValidatorResult.success());""";
    // Vulnerable: SPR-039
    String snippet_62 = """oauth2Client.tokenUri(tokenUri);""";
    // Vulnerable: SPR-040
    String snippet_63 = """String state = UUID.randomUUID().toString(); redirect("/oauth2/authorization/keycloak?state=" + state);""";
    // Vulnerable: SPR-041
    String snippet_64 = """String redirect = req.getParameter("redirect_uri"); return "redirect:" + redirect;""";
    // Vulnerable: SPR-042
    String snippet_65 = """http.sessionManagement(s -> s.sessionFixation(f -> f.none()));""";
    // Vulnerable: SPR-043
    String snippet_66 = """CompletableFuture.runAsync(() -> service.handle(SecurityContextHolder.getContext()));""";
    // Vulnerable: SPR-044
    String snippet_67 = """http.csrf(csrf -> csrf.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.ALWAYS));""";
    // Vulnerable: SPR-045
    String snippet_68 = """@GetMapping("/api/search") return service.heavyElasticSearch(q, filters);""";
    // Vulnerable: SPR-046
    String snippet_69 = """return reportClient.fetchLargeReport(id);""";
    // Vulnerable: SPR-047
    String snippet_70 = """log.info("auth={}", request.getHeader("Authorization"));""";
    // Vulnerable: SPR-048
    String snippet_71 = """tracer.currentSpan().tag("user.email", user.getEmail()); tracer.currentSpan().tag("ssn", req.ssn());""";
    // Vulnerable: SPR-049
    String snippet_72 = """management.endpoints.web.exposure.include=health,info,heapdump management.endpoint.heapdump.enabled=true""";
    // Vulnerable: SPR-050
    String snippet_73 = """@PostMapping("/users") public User create(@RequestBody User entity){ return repo.save(entity); }""";
    // Vulnerable: SPR-051
    String snippet_74 = """objectMapper.readerForUpdating(user).readValue(jsonPatchBody); repo.save(user);""";
    // Vulnerable: SPR-052
    String snippet_75 = """return ResponseEntity.status(500).body(Map.of("error", ex.toString(), "trace", stackTrace(ex)));""";
    // Vulnerable: SPR-053
    String snippet_76 = """server.error.include-stacktrace=always server.error.include-message=always""";
    // Vulnerable: SPR-054
    String snippet_77 = """@GetMapping("/api/es") return es.search(query, request.getParameter("size"));""";

    // Vulnerable: DB-001
    String snippet_78 = """String q = "select * from orders where status = '" + status + "' and tenant_id=" + tenantId; entityManager.createNativeQuery(q, Order.class).getResultList();""";
    // Vulnerable: DB-002
    String snippet_79 = """spring.datasource.username=app_owner""";
    // Vulnerable: DB-003
    String snippet_80 = """CREATE TABLE customer_secret ( id uuid primary key, pan text not null );""";
    // Vulnerable: DB-004
    String snippet_81 = """String sql = "SELECT * FROM doc WHERE owner_id=" + ownerId;""";
    // Vulnerable: DB-005
    String snippet_82 = """statement.execute("SET row_security = off");""";
    // Vulnerable: DB-006
    String snippet_83 = """String raw = rs.getString("payload"); Object o = mapper.readValue(raw, Object.class);""";
    // Vulnerable: DB-007
    String snippet_84 = """Stream<Order> s = repo.streamAll(); s.forEach(this::heavyWork);""";

    // Vulnerable: ES-001
    String snippet_85 = """String body = request.getParameter("q"); esClient.search(new SearchRequest("orders"), RequestOptions.DEFAULT, body);""";
    // Vulnerable: ES-002
    String snippet_86 = """xpack.security.enabled: false http.host: 0.0.0.0""";
    // Vulnerable: ES-003
    String snippet_87 = """log.info("indexing customer payload={}", objectMapper.writeValueAsString(customer)); indexRequest.source(customerMap);""";
    // Vulnerable: ES-004
    String snippet_88 = """static SearchSourceBuilder SHARED = new SearchSourceBuilder(); SHARED.query(userQuery); client.search(new SearchRequest("idx").source(SHARED), DEFAULT);""";

    // Vulnerable: INF-001
    String snippet_89 = """FROM eclipse-temurin:21-jre
COPY app.jar /app.jar
ENTRYPOINT ["java","-jar","/app.jar"]""";
    // Vulnerable: INF-002
    String snippet_90 = """docker run myapp:latest""";
    // Vulnerable: INF-003
    String snippet_91 = """resources: {}""";
    // Vulnerable: INF-004
    String snippet_92 = """securityContext: {}""";
    // Vulnerable: INF-005
    String snippet_93 = """server {
  listen 443 ssl;
}""";
    // Vulnerable: INF-006
    String snippet_94 = """proxy_set_header Authorization ...;
log_format main '... ...';""";
    // Vulnerable: INF-007
    String snippet_95 = """paths:
- /actuator
- /""";
    // Vulnerable: INF-008
    String snippet_96 = """location /api/ { proxy_pass http://app; }""";

    // Vulnerable: CAM-025
    String snippet_97 = """String cb = (String) execution.getVariable("callbackUrl");
webClient.post().uri(cb).retrieve().toBodilessEntity().block();""";
    // Vulnerable: CAM-026
    String snippet_98 = """runtimeService.createSignalEvent(signalName).send();
audit.log("forwarded signal=" + signalName);""";
    // Vulnerable: CAM-027
    String snippet_99 = """runtimeService.createMessageCorrelation("TenantEvent").processInstanceBusinessKey(key).correlate();""";
    // Vulnerable: CAM-028
    String snippet_100 = """historyService.createHistoricDetailQuery().list();""";
    // Vulnerable: CAM-029
    String snippet_101 = """execution.setVariable("res", shell.evaluate(userScript));""";
    // Vulnerable: CAM-030
    String snippet_102 = """throw new BpmnError(request.getErrorCode());""";

    // Vulnerable: SPR-071
    String snippet_103 = """String u = req.url();
restTemplate.getForObject(u, String.class);""";
    // Vulnerable: SPR-072
    String snippet_104 = """webClient.get().uri(request.getTarget()).retrieve().bodyToMono(String.class);""";
    // Vulnerable: SPR-073
    String snippet_105 = """eureka.client.serviceUrl.defaultZone=http://eureka.internal:8761/eureka""";
    // Vulnerable: SPR-074
    String snippet_106 = """spring.cloud.config.server.git.uri=https://git.example/config
spring.cloud.config.fail-fast=false""";
    // Vulnerable: SPR-075
    String snippet_107 = """requestTemplate.header("Authorization", inboundAuth);
return feignClient.call(target);""";
    // Vulnerable: SPR-076
    String snippet_108 = """requestTemplate.header("X-Forwarded-Host", request.getHeader("X-Forwarded-Host"));""";
    // Vulnerable: SPR-077
    String snippet_109 = """Object evt = mapper.readValue(record.value(), Object.class);
handler.handle(evt);""";
    // Vulnerable: SPR-078
    String snippet_110 = """catch (Exception ex) { throw ex; }
container.setDefaultRequeueRejected(true);""";
    // Vulnerable: SPR-079
    String snippet_111 = """log.warn("invalid message=" + record.value());""";
    // Vulnerable: SPR-080
    String snippet_112 = """spring.cloud.stream.kafka.binder.brokers=kafka:9092
spring.cloud.stream.bindings.input.group=orders""";
    // Vulnerable: SPR-081
    String snippet_113 = """String sortExpr = prefRepo.findByUser(uid).getSortExpr();
entityManager.createNativeQuery("select * from invoice order by " + sortExpr).getResultList();""";
    // Vulnerable: SPR-082
    String snippet_114 = """String filter = reportTemplate.getFilter();
entityManager.createQuery("from Payment p where " + filter).getResultList();""";
    // Vulnerable: SPR-083
    String snippet_115 = """@JsonView(Views.Public.class)
public UserEntity getUser(...) { return repo.findById(id).orElseThrow(); }""";
    // Vulnerable: SPR-084
    String snippet_116 = """auditReader.createQuery().forRevisionsOfEntity(Account.class, true, true).getResultList();""";
    // Vulnerable: SPR-085
    String snippet_117 = """return Mono.fromCallable(() -> repo.findAll()).map(this::toDto);""";
    // Vulnerable: SPR-086
    String snippet_118 = """return webClient.get().uri(path).retrieve().bodyToMono(String.class).map(v -> legacyClient.blockingCall(v));""";
    // Vulnerable: SPR-087
    String snippet_119 = """return authz.check().flatMap(ok -> service.read(accountId));""";
    // Vulnerable: SPR-088
    String snippet_120 = """AtomicReference<String> principal = new AtomicReference<>();
flux.parallel().runOn(Schedulers.parallel()).doOnNext(x -> principal.set(x.user())).sequential();""";
    // Vulnerable: SPR-089
    String snippet_121 = """Flux.interval(Duration.ofMillis(1)).map(this::expensive).subscribe();""";
    // Vulnerable: SPR-090
    String snippet_122 = """return Flux.generate(sink -> sink.next(loadHeavyPayload()));""";
    // Vulnerable: SPR-091
    String snippet_123 = """Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, key);""";
    // Vulnerable: SPR-092
    String snippet_124 = """PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, 256);""";
    // Vulnerable: SPR-093
    String snippet_125 = """HttpClient.create().secure(s -> s.sslContext(SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)));""";
    // Vulnerable: SPR-094
    String snippet_126 = """eventRepo.save(new EventEntity(userId, payloadJson));""";
    // Vulnerable: SPR-095
    String snippet_127 = """ManagedChannel ch = ManagedChannelBuilder.forAddress(host, 8443).useTransportSecurity().build();""";
    // Vulnerable: SPR-096
    String snippet_128 = """Transformer t = TransformerFactory.newInstance().newTransformer(new StreamSource(userXslt));""";
    // Vulnerable: SPR-097
    String snippet_129 = """ZipEntry entry; while((entry = zis.getNextEntry()) != null) { byte[] b = zis.readAllBytes(); }""";
    // Vulnerable: SPR-098
    String snippet_130 = """File f = new File(outDir, entry.getName());
FileOutputStream fos = new FileOutputStream(f);""";
    // Vulnerable: SPR-099
    String snippet_131 = """LocateRegistry.createRegistry(1099);
mbsc.createMBean("javax.management.loading.MLet", ...);""";
    // Vulnerable: SPR-100
    String snippet_132 = """if (inputToken.equals(storedToken)) { return true; }""";
    // Vulnerable: SPR-101
    String snippet_133 = """management.endpoint.env.show-values=always""";
    // Vulnerable: SPR-102
    String snippet_134 = """logger.info("Context: " + request.getHeader("X-Context"));""";
    // Vulnerable: SPR-103
    String snippet_135 = """BeanUtils.copyProperties(dest, orig);""";

    // Vulnerable: DB-008
    String snippet_136 = """copy table from program 'curl http://...';""";
    // Vulnerable: INF-009
    String snippet_137 = """resources: {}
limits: {}""";
  }
}
