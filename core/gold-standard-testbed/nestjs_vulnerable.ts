// Vulnerable: NST-001 (Prototype pollution)
Object.assign(target, req.body);
const dto = req.body
Object.assign(target, dto)

// Vulnerable: NST-002 (Insecure CORS)
app.enableCors({ origin: "*", credentials: true });

// Vulnerable: NST-003 (Missing ValidationPipe)
const appNest = await NestFactory.create(AppModule);
const app = await NestFactory.create(AppModule)

// Vulnerable: NST-004 (TypeORM SQL injection)
await dataSource.query("SELECT * FROM users WHERE email = '" + email + "'");
const q = "SELECT * FROM users WHERE email = '" + email + "'"
await dataSource.query(q)

// Vulnerable: NST-005 (Prisma raw unsafe)
await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + id);

// Vulnerable: NST-006 (Open redirect)
return res.redirect(req.query.next as string);

// Vulnerable: NST-007 (Hardcoded secret)
const jwtSecret = "nest-prod-secret";

// Vulnerable: NST-008 (JWT verify without alg allowlist)
jwt.verify(token, secret);

// Vulnerable: NST-009 (No body size limit)
app.use(express.json());

// Vulnerable: NST-010 (Verbose exception leak)
catch (e) {
  throw new HttpException(e.message, 500);
}
catch (e) {
  throw new HttpException(e.message, 500)
}

// Vulnerable: NST-011 (Info leak in Swagger DTO)
class UserDto {
  password: string;
}
class UserDto {
  password: string
}

// Vulnerable: NST-012 (Unsafe implicit type conversion)
app.useGlobalPipes(
  new ValidationPipe({
    transform: true,
    transformOptions: { enableImplicitConversion: true },
  }),
);
app.useGlobalPipes(new ValidationPipe({ transform: true, transformOptions: { enableImplicitConversion: true } }))

// Vulnerable: NST-013 (Raw HTML in template)
return res.render("page", { userContent });
// {{{ userContent }}}

// Vulnerable: NST-014 (SSRF in HttpService)
return this.httpService.get(url);

// Vulnerable: NST-015 (Missing Rate Limiting)
@Module({
  imports: [],
})
export class AppModule {}

// Vulnerable: NST-016 (Insecure Reflector usage)
const roles = this.reflector.get("roles", context.getClass());

// Vulnerable: NST-017 (File upload without magic number check)
@UseInterceptors(FileInterceptor("file"))
if (!file.originalname.endsWith(".png")) throw new BadRequestException();

// Vulnerable: NST-018 (Insecure bcrypt rounds)
const hash = await bcrypt.hash(pass, 1);

// Vulnerable: NST-019 (XXE in xml2js)
await parseStringPromise(xmlData);

// Vulnerable: NST-020 (Log injection)
this.logger.log(userInput);
