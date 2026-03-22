// Vulnerable: NJS-001
import { exec } from "node:child_process";
exec("tar -xf " + userArchive);

// Vulnerable: NJS-002
import fs from "node:fs";
const unsafePath = baseDir + "/" + req.query.file;
fs.readFileSync(unsafePath, "utf8");

// Vulnerable: NJS-003
import zlib from "node:zlib";
app.get("/inflate", (req, res) => {
  const payload = fs.readFileSync("/tmp/blob.bin");
  const out = zlib.inflateSync(payload);
  res.send(out);
});

// Vulnerable: NJS-004
import serialize from "node-serialize";
const profile = serialize.unserialize(req.body.payload);
const dynamic = eval("(" + req.body.raw + ")");

// Vulnerable: NJS-005
// no process.on("uncaughtException")
// no process.on("unhandledRejection")

// Vulnerable: NJS-006
res.redirect(req.query.next as string);

// Vulnerable: NJS-007
const remote = await fetch(req.body.url);
const data = await remote.text();

// Vulnerable: NJS-008
app.use(cors({ origin: "*", credentials: true }));

// Vulnerable: NJS-009
import jwt from "jsonwebtoken";
const decoded = jwt.verify(token, secret);

// Vulnerable: NJS-010
app.use((err: any, req: any, res: any, _next: any) => {
  res.status(500).json({ error: err.stack });
});

// Vulnerable: NJS-011
function unsafeMerge(target: any, source: any) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
unsafeMerge(config, req.body);

// Vulnerable: NJS-012
const raw = Buffer.allocUnsafe(256);

// Vulnerable: NJS-013
const accountId = req.query.id;
if ((accountId as any).includes("admin")) {
  elevate();
}

// Vulnerable: NJS-014
import vm from "node:vm";
vm.runInNewContext(req.body.code, {});

// Vulnerable: NJS-015
const dangerous = /(a+)+$/;
if (dangerous.test(req.body.input)) {
  processInput(req.body.input);
}

// Vulnerable: NJS-016
app.get("/orders/:id", async (req: any, res: any) => {
  const order = await repo.findById(req.params.id);
  return res.json(order);
});

// Vulnerable: NJS-017
// package.json contains: "internal-lib": "git+https://github.com/org/internal-lib.git"
// no package-lock.json or npm-shrinkwrap.json

// Vulnerable: NJS-018
// helmet() is not used
// app.disable("x-powered-by") is missing

// Vulnerable: NJS-019
if (process.env.VIP_MODE === "1") {
  approveTransfer();
}

// Vulnerable: NJS-020
import fsExtra from "node:fs";
fsExtra.unlink(req.body.filePath, () => undefined);

// Vulnerable: NJS-021
app.use(express.json());

// Vulnerable: NJS-022
import bcrypt from "bcrypt";
const weakHash = await bcrypt.hash(password, 4);

// Vulnerable: NJS-023
const userDoc = await User.find({ email: req.body.email });

// Vulnerable: NJS-024
res.cookie("sid", sessionId);

// Vulnerable: NJS-025
app.use(cors({ methods: "*", allowedHeaders: "*" }));

// Vulnerable: NJS-026
await User.create(req.body);
await User.update(req.body, { where: { id: req.params.id } });

// Vulnerable: NJS-027
const rawBuf = Buffer.from(dynamicInput);

// Vulnerable: NJS-028
// package.json scripts example: { "build": "tsc", "test": "jest" } // no npm audit / snyk / socket

// Vulnerable: NJS-029
const tpl = "<%- userContent %>";

// Vulnerable: NJS-030
app.use(bodyParser.json());

// Vulnerable: NJS-031
const mergedConfig = { ...defaults, ...req.body };

// Vulnerable: NJS-032
const jwtSecret = process.env.JWT_SECRET;

// Vulnerable: NJS-033
https.request({ host: "api.internal", rejectUnauthorized: false });

// Vulnerable: NJS-034
readable.pipe(writable);

// Vulnerable: NJS-035
let passwordPlain = req.body.password;
