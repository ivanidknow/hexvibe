// Vulnerable: FTS-001
const unsafe = <div dangerouslySetInnerHTML={{ __html: userHtml }} />;
element.innerHTML = payload;

// Vulnerable: FTS-002
localStorage.setItem("jwt", token);
sessionStorage.setItem("snils", snilsValue);

// Vulnerable: FTS-003
console.log("token", token);
console.error("profile", profile);

// Vulnerable: FTS-004
window.addEventListener("message", (event) => handleMessage(event.data));
targetWindow.postMessage(secretPayload, "*");

// Vulnerable: FTS-005
if (user.role === "admin") {
  order.price = 0;
}

// Vulnerable: FTS-006
const csp = "script-src 'unsafe-inline' 'unsafe-eval'";

// Vulnerable: FTS-007
// no frame-ancestors and no X-Frame-Options

// Vulnerable: FTS-008
const sourceMapEnabled = true; // app.js.map published

// Vulnerable: FTS-009
const scriptTag = '<script src="https://cdn.example.com/lib.js"></script>';

// Vulnerable: FTS-010
self.addEventListener("fetch", (event) => {
  event.respondWith(caches.match(event.request) || fetch(event.request));
});

// Vulnerable: FTS-011
eval(userInput);
const runDynamic = new Function("a", "b", "return a + b");
setTimeout("dangerousCall()", 1000);
setInterval("poll()", 5000);

// Vulnerable: FTS-012
function deepMerge(target: any, source: any) {
  Object.keys(source).forEach((key) => {
    if (typeof source[key] === "object") {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  });
  return target;
}

// Vulnerable: FTS-013
leakedGlobal = 1;
Array.prototype.custom = function custom() {
  return this;
};

// Vulnerable: FTS-014
const sessionId = Math.random().toString(36).slice(2);

// Vulnerable: FTS-015
const redos = /(a+)+$/;
redos.test(userControlledInput);

// Vulnerable: FTS-016
for (const id of ids) {
  await fetchUser(id);
}
items.map(async (item) => await apiCall(item));

// Vulnerable: FTS-017
window.addEventListener("message", (event) => {
  const payload = JSON.parse(event.data);
  processPayload(payload);
});

// Vulnerable: FTS-018
if (!isAdmin) {
  adminPanel.style.display = "none";
}
document.getElementById("transfer-limit")?.classList.add("hidden");

// Vulnerable: FTS-019
if (role == "admin") {
  grantSensitiveAccess();
}
if (isOwner != false) {
  allowTransfer();
}

// Vulnerable: FTS-020
doCritical().then(saveAudit);
async function runCriticalFlow() {
  await stepOne();
  await stepTwo();
}
