# Node.js / NestJS

## Stack overview

**NestJS** / Express patterns: validation pipes, ORM raw queries, CORS, JWT, throttling, and logging. Metrics are prefixed **`NST`**.

## Top threats

- Prototype pollution and CORS (`NST-001`, `NST-002`).
- SQL/Prisma injection and SSRF (`NST-004`, `NST-005`, `NST-014`).
- AuthZ and guard mistakes (`NST-006`, `NST-008`, `NST-015`, `NST-016`).

## Pattern catalog

Complete Anti-Pattern / Safe-Pattern definitions live in [`patterns.md`](patterns.md). The table below is a **table of contents** by metric ID.

| ID | Metric | Stack |
|---|---|---|
| `NST-001` | Prototype Pollution в DTO merge | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-002` | Insecure CORS (`origin: *`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-003` | Missing global ValidationPipe | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-004` | TypeORM SQL Injection (query string concat) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-005` | Prisma Raw Injection (`$queryRawUnsafe`) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-006` | Open Redirect in controller | `CWE-601` |
| `NST-007` | Hardcoded secrets in source | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-008` | JWT verify without algorithm allowlist | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-009` | Missing body size limits | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-010` | Verbose exception leak | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-011` | Info leak in Swagger DTO | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-012` | Unsafe implicit type conversion | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-013` | Raw HTML in template rendering | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-014` | SSRF in `HttpService` | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-015` | Missing rate limiting in root module | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-016` | Insecure Reflector usage in Guard | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-017` | File upload without magic number check | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-018` | Insecure bcrypt rounds | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-019` | XXE risk in xml2js parsing | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-020` | Log Injection | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-021` | CSV Injection in Node/NestJS export handlers (CWE-1236) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-022` | Debug message disclosure in production exception filter (CWE-1295) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-023` | CSV export from untrusted DTO fields without normalization (CWE-1236) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-024` | `localStorage` с access/refresh токенами (CWE-312) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-025` | PII в `localStorage` как JSON (CWE-312) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NST-026` | Refresh token в `sessionStorage` без ротации (CWE-532) | Validate data with Zod and sanitize DOM/HTML sinks with DOMPurify before rendering. |
| `NSX-101` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-102` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-103` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-104` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-105` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-106` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-107` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-108` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-109` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-110` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-111` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-112` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-113` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-114` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-115` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-116` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-117` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-118` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-119` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-120` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-121` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-122` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-123` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-124` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-125` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-126` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-127` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-128` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-129` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-130` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-131` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-132` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-133` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-134` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-135` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-136` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-137` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-138` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-139` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-140` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-141` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-142` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-143` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-144` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-145` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-146` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-147` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-148` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-149` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-150` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-151` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-152` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-153` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-154` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-155` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-156` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-157` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-158` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-159` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-160` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-161` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-162` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-163` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-164` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-165` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-166` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-167` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-168` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-169` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-170` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-171` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-172` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-173` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-174` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-175` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-176` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-177` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-178` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-179` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-180` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-181` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-182` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-183` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-184` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-185` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-186` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-187` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-188` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-189` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-190` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-191` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-192` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-193` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-194` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-195` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-196` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-197` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-198` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-199` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-200` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-201` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-202` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-203` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-204` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-205` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-206` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-207` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-208` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-209` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-210` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-211` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-212` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-213` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-214` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-215` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-216` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-217` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-218` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-219` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-220` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-221` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-222` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-223` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-224` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-225` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-226` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-227` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-228` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-229` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-230` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-231` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-232` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-233` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-234` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-235` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-236` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-237` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-238` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-239` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-240` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-241` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-242` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-243` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-244` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-245` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-246` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-247` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-248` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-249` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-250` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-251` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-252` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-253` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-254` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-255` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-256` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-257` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-258` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-259` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-260` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-261` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-262` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-263` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-264` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-265` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-266` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-267` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-268` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-269` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-270` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-271` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-272` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-273` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-274` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-275` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-276` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-277` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-278` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-279` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-280` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-281` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-282` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-283` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-284` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-285` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-286` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-287` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-288` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-289` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-290` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-291` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-292` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-293` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-294` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-295` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-296` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-297` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-298` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-299` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-300` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-301` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-302` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-303` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-304` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-305` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `NSX-306` | NestJS prototype pollution via Object.assign on DTO | Autofix: replace direct assign with allowlisted key mapping. |
| `NSX-307` | Sandbox escape risk in vm module with untrusted code | Autofix: block untrusted vm execution and move to fixed command dispatch. |
| `NSX-308` | JWT verification without strict algorithm allowlist | Autofix: enforce explicit algorithms issuer and audience checks. |
| `NSX-309` | NestJS IDOR on route param (Logic: strong) | Autofix: bind object query to authenticated ownerId. |
| `NSX-310` | NestJS mass assignment through plainToInstance | Autofix: map DTO into explicit allowlist fields before entity binding. |
| `IFN-001` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-002` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-003` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-004` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-005` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-006` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-007` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-008` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-009` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-010` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-011` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-012` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-013` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-014` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-015` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-016` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-017` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-018` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-019` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-020` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-021` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-022` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-023` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-024` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-025` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-026` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-027` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-028` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-029` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-030` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-031` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-032` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-033` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-034` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-035` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-036` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-037` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-038` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-039` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-040` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-041` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-042` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-043` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-044` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-045` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-046` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-047` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-048` | Node.js/NestJS: security config exists but not bound to endpoint chain (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-049` | Node.js/NestJS: missing global guard on controller route (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `IFN-050` | Node.js/NestJS: controller data access bypasses security context (Logic: strong) | Autofix: bind controller access to global guard/interceptor and owner-scoped repository methods. |
| `NST-027` | Semgrep: angular-bypasssecuritytrust | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-028` | Semgrep: Moment is a legacy project in maintenance mode. Consider using libraries that ... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-029` | Semgrep: It looks like no matter how $CONDITION is evaluated, this expression returns $... | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-030` | Semgrep: nestjs-header-cors-any | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-031` | Semgrep: react-find-dom | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-032` | Semgrep: react-legacy-component | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-033` | Semgrep: react-props-in-state | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-034` | Semgrep: react-props-spreading | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-035` | Semgrep: Translation key '$KEY' should match format 'MODULE.FEATURE.* | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-036` | Semgrep: JSX Component label not internationalized: '$MESSAGE | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-037` | Semgrep: jsx-not-internationalized | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-038` | Semgrep: React MUI enqueueSnackbar() title is not internationalized: ''$MESSAGE | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-039` | Semgrep: useselect-label-not-i18n | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-040` | Semgrep: react-dangerouslysetinnerhtml | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-041` | Semgrep: react-href-var | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-042` | Semgrep: react-jwt-decoded-property | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-043` | Semgrep: react-jwt-in-localstorage | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-044` | Semgrep: react-unsanitized-method | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-045` | Semgrep: react-unsanitized-property | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-046` | Semgrep: react-insecure-request | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |
| `NST-047` | Semgrep: react-markdown-insecure-html | Атакующий доставляет входные данные, соответствующие anti-pattern; реальный ущерб зависит от приёмника (sink), конфигурации и границ доверия. |

## Verification

**Verification:** Check the gold testbed file(s) below for `Vulnerable: <ID>` markers (static Semgrep + `detection-matrix.md` ground truth).

- [`gold-standard-testbed/nestjs_vulnerable.ts`](../gold-standard-testbed/nestjs_vulnerable.ts)

After changing [`patterns.md`](patterns.md), run from the repo root:

```bash
python scripts/sync_semgrep.py
```

## Workflow: Recon → Scan → Verify

### 1) Recon
- Map entrypoints, data flows, and trust boundaries for this stack.
- Identify which metrics in [`patterns.md`](patterns.md) apply to the code under review.

### 2) Scan
- Run Semgrep with `semgrep-rules/<skill>.yaml` (generated) and correlate with Anti-Patterns.
- Eliminate findings that cannot bind to a metric row.

### 3) Verify
- Confirm markers or scanner hits for touched IDs in the gold testbed when adding metrics.
- Emit findings as `Vulnerable: <PREFIX>-<NNN>` in written reviews.

