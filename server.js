const http = require("http");
const fs = require("fs");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");

const PORT = 3000;

const MAX_BYTES = 3 * 1024 * 1024;
const TIMEOUT = 12000;

function send(res, status, type, body) {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store"
  });

  res.end(body);
}

function json(res, status, data) {
  send(
    res,
    status,
    "application/json; charset=utf-8",
    JSON.stringify(data, null, 2)
  );
}

function normalizeText(value) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim();
}

function absoluteUrl(value, base) {
  try {
    return new URL(value, base).href;
  } catch {
    return null;
  }
}

function hostnameOf(value) {
  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(n => Number.isNaN(n))
  ) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIPv6(ip) {
  const x = ip.toLowerCase();

  return (
    x === "::1" ||
    x === "::" ||
    x.startsWith("fc") ||
    x.startsWith("fd") ||
    x.startsWith("fe80:")
  );
}

function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    return isPrivateIPv4(ip);
  }

  if (net.isIPv6(ip)) {
    return isPrivateIPv6(ip);
  }

  return false;
}

async function validateTarget(target) {
  let url;

  try {
    url = new URL(target);
  } catch {
    throw new Error("URL tidak valid.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error(
      "Hanya URL HTTP dan HTTPS yang diperbolehkan."
    );
  }

  if (
    url.username ||
    url.password
  ) {
    throw new Error(
      "URL dengan username/password tidak diperbolehkan."
    );
  }

  const hostname = url.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new Error(
      "Target lokal/internal tidak diperbolehkan."
    );
  }

  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error(
        "Target mengarah ke alamat IP privat/lokal."
      );
    }

    return url.href;
  }

  let addresses;

  try {
    addresses = await dns.lookup(hostname, {
      all: true
    });
  } catch {
    throw new Error(
      "Hostname tidak dapat ditemukan melalui DNS."
    );
  }

  for (const item of addresses) {
    if (isPrivateAddress(item.address)) {
      throw new Error(
        "Target mengarah ke jaringan privat/lokal."
      );
    }
  }

  return url.href;
}

async function fetchTarget(target) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    TIMEOUT
  );

  try {
    const response = await fetch(target, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,

      headers: {
        "User-Agent":
          "SIGINT-9-Safe-Inspector/2.0",
        "Accept":
          "text/html,application/xhtml+xml"
      }
    });

    const location =
      response.headers.get("location");

    /*
      Redirect diperiksa satu per satu.
      Kita validasi tujuan redirect sebelum mengikutinya.
    */

    if (
      response.status >= 300 &&
      response.status < 400 &&
      location
    ) {
      const redirected =
        absoluteUrl(location, target);

      if (!redirected) {
        throw new Error(
          "Redirect URL tidak valid."
        );
      }

      return {
        redirect: true,
        location: redirected,
        status: response.status,
        headers: Object.fromEntries(
          response.headers.entries()
        )
      };
    }

    const contentType =
      response.headers.get("content-type") || "";

    if (
      !contentType.includes("text/html") &&
      !contentType.includes("application/xhtml+xml")
    ) {
      throw new Error(
        `Target bukan HTML (${contentType || "unknown"})`
      );
    }

    const reader =
      response.body.getReader();

    const chunks = [];
    let total = 0;

    while (true) {
      const {
        value,
        done
      } = await reader.read();

      if (done) break;

      total += value.length;

      if (total > MAX_BYTES) {
        await reader.cancel();

        throw new Error(
          "HTML target terlalu besar."
        );
      }

      chunks.push(Buffer.from(value));
    }

    const html =
      Buffer.concat(chunks).toString("utf8");

    return {
      redirect: false,
      html,
      finalURL: response.url || target,
      status: response.status,
      contentType,
      headers: Object.fromEntries(
        response.headers.entries()
      )
    };

  } finally {
    clearTimeout(timer);
  }
}

function extractTitle(html) {
  const match =
    html.match(
      /<title[^>]*>([\s\S]*?)<\/title>/i
    );

  return match
    ? normalizeText(
        match[1]
          .replace(/<[^>]+>/g, "")
      )
    : "";
}

function extractMetaDescription(html) {
  const match =
    html.match(
      /<meta[^>]+name\s*=\s*["']description["'][^>]+content\s*=\s*["']([^"']*)["']/i
    );

  return match
    ? normalizeText(match[1])
    : "";
}

function getTags(html, tag) {
  return [
    ...html.matchAll(
      new RegExp(
        `<${tag}\\b[^>]*>`,
        "gi"
      )
    )
  ].map(x => x[0]);
}

function getAttribute(tag, name) {
  const regex =
    new RegExp(
      `${name}\\s*=\\s*["']([^"']*)["']`,
      "i"
    );

  const match = tag.match(regex);

  return match
    ? match[1]
    : null;
}

function analyzeHTML(
  html,
  targetURL,
  finalURL,
  headers
) {
  const findings = [];
  let score = 0;

  const add = (
    severity,
    category,
    title,
    detail,
    points
  ) => {
    findings.push({
      severity,
      category,
      title,
      detail,
      points
    });

    score += points;
  };

  const lower =
    html.toLowerCase();

  const title =
    extractTitle(html);

  const description =
    extractMetaDescription(html);

  /*
  ==========================
  FORMS
  ==========================
  */

  const forms =
    getTags(html, "form");

  const passwordFields =
    (
      html.match(
        /<input[^>]+type\s*=\s*["']password["']/gi
      ) || []
    ).length;

  const emailFields =
    (
      html.match(
        /<input[^>]+type\s*=\s*["']email["']/gi
      ) || []
    ).length;

  const submitButtons =
    (
      html.match(
        /type\s*=\s*["']submit["']/gi
      ) || []
    ).length;

  if (passwordFields > 0) {
    add(
      "HIGH",
      "phishing",
      "Password field ditemukan",
      `Halaman memiliki ${passwordFields} field password.`,
      20
    );
  }

  if (emailFields > 0) {
    add(
      "MEDIUM",
      "credential",
      "Email field ditemukan",
      `Halaman memiliki ${emailFields} field email.`,
      5
    );
  }

  if (forms.length > 0) {
    add(
      "INFO",
      "form",
      "Form ditemukan",
      `Halaman memiliki ${forms.length} form dan ${submitButtons} tombol submit.`,
      3
    );
  }

  /*
  ==========================
  FORM DESTINATIONS
  ==========================
  */

  const pageHost =
    hostnameOf(finalURL);

  for (const form of forms) {
    const action =
      getAttribute(form, "action");

    if (!action) continue;

    const destination =
      absoluteUrl(
        action,
        finalURL
      );

    if (!destination) continue;

    const destinationHost =
      hostnameOf(destination);

    if (
      destinationHost &&
      destinationHost !== pageHost
    ) {
      add(
        "HIGH",
        "phishing",
        "Form mengirim data ke domain berbeda",
        `Form halaman mengarah ke ${destinationHost}, sedangkan halaman berasal dari ${pageHost}.`,
        30
      );
    }

    if (
      destination.startsWith(
        "http://"
      )
    ) {
      add(
        "HIGH",
        "credential",
        "Form dikirim melalui HTTP",
        "Data form berpotensi dikirim tanpa enkripsi HTTPS.",
        20
      );
    }
  }

  /*
  ==========================
  IFRAMES
  ==========================
  */

  const iframes =
    getTags(html, "iframe");

  if (iframes.length > 0) {
    add(
      "MEDIUM",
      "iframe",
      "Iframe ditemukan",
      `Ditemukan ${iframes.length} iframe.`,
      Math.min(12, iframes.length * 3)
    );
  }

  /*
  ==========================
  SCRIPTS
  ==========================
  */

  const scripts =
    getTags(html, "script");

  if (scripts.length >= 10) {
    add(
      "LOW",
      "script",
      "Jumlah JavaScript cukup banyak",
      `Ditemukan ${scripts.length} elemen script.`,
      5
    );
  }

  /*
  ==========================
  JAVASCRIPT OBFUSCATION
  ==========================
  */

  const jsPatterns = [
    {
      regex: /eval\s*\(/i,
      name: "eval()"
    },
    {
      regex: /atob\s*\(/i,
      name: "atob()"
    },
    {
      regex: /btoa\s*\(/i,
      name: "btoa()"
    },
    {
      regex: /fromCharCode\s*\(/i,
      name: "fromCharCode()"
    },
    {
      regex: /unescape\s*\(/i,
      name: "unescape()"
    },
    {
      regex: /decodeURIComponent\s*\(/i,
      name: "decodeURIComponent()"
    },
    {
      regex: /document\.write\s*\(/i,
      name: "document.write()"
    }
  ];

  const jsHits = [];

  for (const item of jsPatterns) {
    if (item.regex.test(html)) {
      jsHits.push(item.name);
    }
  }

  if (jsHits.length >= 2) {
    add(
      "HIGH",
      "obfuscation",
      "Indikator JavaScript obfuscation",
      `Pola ditemukan: ${jsHits.join(", ")}.`,
      18
    );
  }

  /*
  ==========================
  LARGE BASE64
  ==========================
  */

  const base64 =
    lower.match(
      /[a-z0-9+/]{500,}={0,2}/gi
    );

  if (base64) {
    add(
      "MEDIUM",
      "obfuscation",
      "Blok Base64 besar ditemukan",
      "Terdapat blok string Base64 yang sangat panjang.",
      12
    );
  }

  /*
  ==========================
  PHISHING WORDS
  ==========================
  */

  const phishingWords = [
    "verify your account",
    "verify account",
    "confirm your account",
    "account suspended",
    "account locked",
    "urgent action",
    "security verification",
    "sign in",
    "login",
    "password",
    "wallet",
    "seed phrase",
    "recovery phrase",
    "credit card",
    "bank account",
    "otp",
    "verification code"
  ];

  const wordHits =
    phishingWords.filter(
      word => lower.includes(word)
    );

  if (wordHits.length >= 2) {
    add(
      "HIGH",
      "phishing",
      "Bahasa yang sering digunakan pada phishing",
      `Ditemukan: ${wordHits.slice(0, 8).join(", ")}.`,
      18
    );
  }

  /*
  ==========================
  HIDDEN ELEMENTS
  ==========================
  */

  const hiddenMatches =
    lower.match(
      /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0/g
    ) || [];

  if (hiddenMatches.length >= 5) {
    add(
      "MEDIUM",
      "hidden",
      "Banyak elemen tersembunyi",
      `Ditemukan sekitar ${hiddenMatches.length} indikator hidden.`,
      7
    );
  }

  /*
  ==========================
  DOWNLOADS
  ==========================
  */

  const downloadRegex =
    /\.exe\b|\.apk\b|\.msi\b|\.scr\b|\.bat\b|\.cmd\b|\.ps1\b|application\/octet-stream|download\s*=/i;

  if (downloadRegex.test(lower)) {
    add(
      "HIGH",
      "download",
      "Indikator file yang dapat diunduh",
      "Halaman mengandung referensi download atau file executable.",
      15
    );
  }

  /*
  ==========================
  META REDIRECT
  ==========================
  */

  if (
    /<meta[^>]+http-equiv\s*=\s*["']?refresh/i
      .test(html)
  ) {
    add(
      "MEDIUM",
      "redirect",
      "Meta refresh ditemukan",
      "Halaman memiliki mekanisme redirect melalui meta refresh.",
      10
    );
  }

  /*
  ==========================
  LINKS / DOMAINS
  ==========================
  */

  const references = [
    ...html.matchAll(
      /(?:href|src|action)\s*=\s*["']([^"']+)["']/gi
    )
  ];

  const domains =
    new Set();

  const externalURLs = [];

  for (const match of references) {
    const url =
      absoluteUrl(
        match[1],
        finalURL
      );

    if (!url) continue;

    try {
      const parsed =
        new URL(url);

      if (
        parsed.protocol === "http:" ||
        parsed.protocol === "https:"
      ) {
        domains.add(
          parsed.hostname
        );

        if (
          parsed.hostname !== pageHost
        ) {
          externalURLs.push(url);
        }
      }
    } catch {}
  }

  const externalDomains =
    [...domains]
      .filter(
        d => d !== pageHost
      );

  if (externalDomains.length >= 8) {
    add(
      "LOW",
      "external",
      "Banyak domain eksternal",
      `Ditemukan ${externalDomains.length} domain eksternal.`,
      7
    );
  }

  /*
  ==========================
  DATA URL / JAVASCRIPT URL
  ==========================
  */

  const javascriptURLs =
    (
      html.match(
        /(?:href|src)\s*=\s*["']javascript:/gi
      ) || []
    ).length;

  const dataURLs =
    (
      html.match(
        /(?:href|src)\s*=\s*["']data:/gi
      ) || []
    ).length;

  if (javascriptURLs > 0) {
    add(
      "HIGH",
      "script",
      "JavaScript URL ditemukan",
      `Ditemukan ${javascriptURLs} referensi javascript:`,
      12
    );
  }

  if (dataURLs > 0) {
    add(
      "MEDIUM",
      "obfuscation",
      "Data URL ditemukan",
      `Ditemukan ${dataURLs} referensi data:.`,
      8
    );
  }

  /*
  ==========================
  HTTPS
  ==========================
  */

  try {
    const url =
      new URL(finalURL);

    if (url.protocol !== "https:") {
      add(
        "HIGH",
        "transport",
        "Halaman tidak menggunakan HTTPS",
        "Halaman akhir menggunakan HTTP.",
        12
      );
    }
  } catch {}

  /*
  ==========================
  REDIRECT
  ==========================
  */

  if (targetURL !== finalURL) {
    add(
      "MEDIUM",
      "redirect",
      "URL akhir berbeda",
      `URL akhir: ${finalURL}`,
      12
    );
  }

  /*
  ==========================
  URL COMPLEXITY
  ==========================
  */

  try {
    const original =
      new URL(targetURL);

    if (targetURL.length > 180) {
      add(
        "LOW",
        "url",
        "URL sangat panjang",
        `Panjang URL: ${targetURL.length} karakter.`,
        5
      );
    }

    if (
      original.hostname.includes("xn--")
    ) {
      add(
        "MEDIUM",
        "url",
        "Punycode/IDN hostname",
        "Hostname menggunakan xn--.",
        8
      );
    }

    if (
      original.href.includes("@")
    ) {
      add(
        "HIGH",
        "url",
        "Karakter @ pada URL",
        "Karakter @ dapat digunakan untuk menyamarkan hostname.",
        15
      );
    }

    if (
      original.protocol !== "https:"
    ) {
      add(
        "MEDIUM",
        "transport",
        "URL awal menggunakan HTTP",
        "URL awal tidak menggunakan HTTPS.",
        5
      );
    }
  } catch {}

  /*
  ==========================
  SERVER HEADERS
  ==========================
  */

  const server =
    headers["server"];

  const powered =
    headers["x-powered-by"];

  /*
  ==========================
  FINAL SCORE
  ==========================
  */

  score =
    Math.min(
      100,
      Math.round(score)
    );

  let verdict = "LOW RISK";

  if (score >= 70) {
    verdict = "HIGH RISK";
  } else if (score >= 35) {
    verdict = "SUSPICIOUS";
  }

  const counts = {
    high:
      findings.filter(
        x => x.severity === "HIGH"
      ).length,

    medium:
      findings.filter(
        x => x.severity === "MEDIUM"
      ).length,

    low:
      findings.filter(
        x => x.severity === "LOW"
      ).length,

    info:
      findings.filter(
        x => x.severity === "INFO"
      ).length
  };

  return {
    target: targetURL,
    finalURL,
    title,
    description,
    verdict,
    score,

    statistics: {
      forms: forms.length,
      passwordFields,
      emailFields,
      submitButtons,
      scripts: scripts.length,
      iframes: iframes.length,
      externalDomains:
        externalDomains.length,
      externalURLs:
        externalURLs.length,
      hiddenIndicators:
        hiddenMatches.length,
      javascriptURLs,
      dataURLs,
      findings:
        findings.length
    },

    severityCounts: counts,

    serverHeaders: {
      server: server || null,
      poweredBy: powered || null,
      contentType:
        headers["content-type"] || null
    },

    externalDomains:
      externalDomains.slice(0, 100),

    findings
  };
}

async function scanWithRedirects(
  original
) {
  let current =
    await validateTarget(original);

  const redirectChain = [];

  for (let i = 0; i < 5; i++) {
    const result =
      await fetchTarget(current);

    if (!result.redirect) {
      return {
        result,
        redirectChain
      };
    }

    const next =
      await validateTarget(
        result.location
      );

    redirectChain.push({
      from: current,
      to: next,
      status: result.status
    });

    current = next;
  }

  throw new Error(
    "Terlalu banyak redirect."
  );
}

const server =
  http.createServer(
    async (req, res) => {

      /*
      ==========================
      API
      ==========================
      */

      if (
        req.method === "GET" &&
        req.url.startsWith(
          "/api/scan"
        )
      ) {
        try {
          const parsed =
            new URL(
              req.url,
              `http://0.0.0.0:${PORT}`
            );

          const target =
            parsed.searchParams.get(
              "url"
            );

          if (!target) {
            return json(
              res,
              400,
              {
                error:
                  "Masukkan parameter url."
              }
            );
          }

          const {
            result,
            redirectChain
          } =
            await scanWithRedirects(
              target
            );

          const analysis =
            analyzeHTML(
              result.html,
              target,
              result.finalURL,
              result.headers
            );

          analysis.httpStatus =
            result.status;

          analysis.redirectChain =
            redirectChain;

          return json(
            res,
            200,
            analysis
          );

        } catch (error) {
          return json(
            res,
            400,
            {
              error:
                error.message ||
                "Scan gagal."
            }
          );
        }
      }

      /*
      ==========================
      FRONTEND
      ==========================
      */

      if (
        req.method === "GET"
      ) {
        const filePath =
          path.join(
            __dirname,
            "index.html"
          );

        if (
          !fs.existsSync(filePath)
        ) {
          return send(
            res,
            404,
            "text/plain; charset=utf-8",
            "index.html belum dibuat."
          );
        }

        return send(
          res,
          200,
          "text/html; charset=utf-8",
          fs.readFileSync(
            filePath
          )
        );
      }

      send(
        res,
        404,
        "text/plain; charset=utf-8",
        "Not found"
      );
    }
  );

server.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log("");
    console.log(
      "======================================"
    );
    console.log(
      "       SIGINT-9 SAFE WEB INSPECTOR"
    );
    console.log(
      "======================================"
    );
    console.log("");
    console.log(
      `SERVER: http://0.0.0.0:${PORT}`
    );
    console.log("");
    console.log(
      "Read-only HTML inspection enabled."
    );
    console.log(
      "Target JavaScript/forms are NOT executed."
    );
    console.log(
      "Redirect chain analysis enabled."
    );
    console.log("");
  }
);
