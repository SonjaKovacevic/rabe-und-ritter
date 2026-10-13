'use strict';
// Entschlüsselt die Spieldateien im Browser. Klartext liegt nur im Arbeitsspeicher,
// nie in Cache Storage. Build-Version (wechselt bei jedem Bau):
const VERSION = '20261013-190652-90e643';

const DB = 'spiel-zugang', ABLAGE = 'schluessel', EINTRAG = 'aes';
const BASIS = new URL(self.registration.scope).pathname;   // Pfad der Passwortseite
const SPIEL = BASIS + 'spiel/';
const SPEICHER_GRENZE = 96 * 1024 * 1024;                  // entschlüsselte Bytes im Speicher
const kodierer = new TextEncoder();

class KeinZugang extends Error {}
class Veraltet extends Error {}

let schluesselP = null;          // Promise<CryptoKey|null>
let manifestP = null;            // Promise<{schluessel, dateien}>
let letztes = null;              // zuletzt geladenes Manifest (Rückfall ohne Netz)
const speicher = new Map();      // id -> {p: Promise<ArrayBuffer>, n}
let belegt = 0;

self.addEventListener('install', () => { self.skipWaiting(); });
self.addEventListener('activate', ereignis => { ereignis.waitUntil(self.clients.claim()); });
self.addEventListener('message', ereignis => {
  if (ereignis.data && ereignis.data.typ === 'zugang-geaendert') vergiss();
});

function vergiss() { schluesselP = null; manifestP = null; letztes = null; speicher.clear(); belegt = 0; }

function oeffne() {
  return new Promise((ok, fehler) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(ABLAGE);
    r.onsuccess = () => ok(r.result);
    r.onerror = () => fehler(r.error);
  });
}
async function liesSchluessel() {
  const db = await oeffne();
  try {
    return await new Promise((ok, fehler) => {
      const r = db.transaction(ABLAGE).objectStore(ABLAGE).get(EINTRAG);
      r.onsuccess = () => ok(r.result || null);
      r.onerror = () => fehler(r.error);
    });
  } finally { db.close(); }
}
function holeSchluessel() {
  if (!schluesselP) {
    const p = liesSchluessel().then(w => (w && w.schluessel) || null, () => null);
    schluesselP = p;
    p.then(k => { if (!k && schluesselP === p) schluesselP = null; });   // Fehlen nicht merken
  }
  return schluesselP;
}

function entschluessle(schluessel, puffer, zusatz) {
  if (puffer.byteLength < 28) return Promise.reject(new Error('Datei zu kurz'));
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(puffer, 0, 12), additionalData: kodierer.encode(zusatz) },
    schluessel, new Uint8Array(puffer, 12));
}

async function ladeManifest() {
  const schluessel = await holeSchluessel();
  if (!schluessel) throw new KeinZugang();
  let antwort;
  try {
    antwort = await fetch(BASIS + 'd/m.bin', { cache: 'no-cache' });
    if (!antwort.ok) throw new Error('Manifest: HTTP ' + antwort.status);
  } catch (e) {
    if (letztes) return letztes;                         // kurz offline: bisheriges Manifest weiterverwenden
    throw e;
  }
  let klar;
  try { klar = await entschluessle(schluessel, await antwort.arrayBuffer(), 'm'); }
  catch (e) { vergiss(); throw new KeinZugang(); }    // Passwort geändert oder abgemeldet
  const manifest = { schluessel, dateien: JSON.parse(new TextDecoder().decode(klar)).dateien };
  const ids = new Set(Object.values(manifest.dateien).map(e => e.id));
  for (const [id, e] of speicher) if (!ids.has(id)) { speicher.delete(id); belegt -= e.n; }
  letztes = manifest;
  return manifest;
}
function holeManifest() {
  if (!manifestP) {
    const p = ladeManifest();
    manifestP = p;
    p.catch(() => { if (manifestP === p) manifestP = null; });
  }
  return manifestP;
}

function holeDatei(manifest, eintrag) {
  let e = speicher.get(eintrag.id);
  if (e) { speicher.delete(eintrag.id); speicher.set(eintrag.id, e); return e.p; }
  const p = (async () => {
    const antwort = await fetch(BASIS + 'd/' + eintrag.id + '.bin');
    if (antwort.status === 404) throw new Veraltet();
    if (!antwort.ok) throw new Error('HTTP ' + antwort.status);
    return entschluessle(manifest.schluessel, await antwort.arrayBuffer(), eintrag.id);
  })();
  e = { p, n: eintrag.n || 0 };
  speicher.set(eintrag.id, e);
  belegt += e.n;
  p.catch(() => { if (speicher.get(eintrag.id) === e) { speicher.delete(eintrag.id); belegt -= e.n; } });
  while (belegt > SPEICHER_GRENZE && speicher.size > 1) {
    const [aeltesteId, aelteste] = speicher.entries().next().value;
    speicher.delete(aeltesteId);
    belegt -= aelteste.n;
  }
  return p;
}

function pfadVon(url) {
  let rest = url.pathname.slice(SPIEL.length);
  try { rest = decodeURIComponent(rest); } catch (e) { return null; }
  rest = rest.normalize('NFC');
  if (rest === '' || rest.endsWith('/')) rest += 'index.html';
  return rest;
}

const hat = (objekt, schluessel) => Object.prototype.hasOwnProperty.call(objekt, schluessel);
const text = (status, inhalt) => new Response(inhalt, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

function baueAntwort(anfrage, daten, typ) {
  const groesse = daten.byteLength;
  const kopf = { 'Content-Type': typ, 'Accept-Ranges': 'bytes' };
  const kopfzeile = anfrage.headers.get('Range');
  const m = kopfzeile && /^bytes=(\d*)-(\d*)$/.exec(kopfzeile.trim());
  if (m && (m[1] !== '' || m[2] !== '')) {
    let start, ende;
    if (m[1] === '') {                                   // bytes=-N (die letzten N Bytes)
      const n = Number(m[2]);
      start = Math.max(0, groesse - n);
      ende = n === 0 ? -1 : groesse - 1;
    } else {
      start = Number(m[1]);
      ende = m[2] === '' ? groesse - 1 : Math.min(Number(m[2]), groesse - 1);
    }
    if (start >= groesse || ende < start) {
      return new Response(null, { status: 416, headers: Object.assign(kopf, { 'Content-Range': 'bytes */' + groesse }) });
    }
    const laenge = ende - start + 1;
    return new Response(anfrage.method === 'HEAD' ? null : new Uint8Array(daten, start, laenge), {
      status: 206,
      headers: Object.assign(kopf, { 'Content-Range': 'bytes ' + start + '-' + ende + '/' + groesse, 'Content-Length': String(laenge) })
    });
  }
  return new Response(anfrage.method === 'HEAD' ? null : daten, {
    status: 200, headers: Object.assign(kopf, { 'Content-Length': String(groesse) })
  });
}

async function antworte(anfrage, url, zweiterVersuch) {
  // Bei jedem Seitenaufruf Schlüssel und Manifest neu prüfen: so greifen Abmelden,
  // Passwortwechsel und neue Builds sofort.
  if (anfrage.mode === 'navigate' && !zweiterVersuch) { schluesselP = null; manifestP = null; }
  let manifest;
  try { manifest = await holeManifest(); }
  catch (e) {
    if (e instanceof KeinZugang) {
      return anfrage.mode === 'navigate' ? Response.redirect(self.registration.scope, 302) : text(401, 'Kein Zugang');
    }
    return text(503, 'Das Spiel konnte nicht geladen werden. Bitte die Internetverbindung prüfen.');
  }
  const pfad = pfadVon(url);
  if (pfad === null || !hat(manifest.dateien, pfad)) {
    if (pfad !== null && hat(manifest.dateien, pfad + '/index.html')) {
      return Response.redirect(new URL(url.pathname + '/' + url.search, url).href, 301);
    }
    return text(404, 'Nicht gefunden');
  }
  const eintrag = manifest.dateien[pfad];
  let daten;
  try { daten = await holeDatei(manifest, eintrag); }
  catch (e) {
    if (e instanceof Veraltet && !zweiterVersuch) {    // neuer Build veröffentlicht: Manifest neu laden
      manifestP = null;
      return antworte(anfrage, url, true);
    }
    return text(503, 'Das Spiel konnte nicht geladen werden.');
  }
  return baueAntwort(anfrage, daten, eintrag.typ);
}

self.addEventListener('fetch', ereignis => {
  const anfrage = ereignis.request;
  if (anfrage.method !== 'GET' && anfrage.method !== 'HEAD') return;
  const url = new URL(anfrage.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname === BASIS + 'spiel') {
    ereignis.respondWith(Response.redirect(new URL(SPIEL + url.search, url).href, 301));
    return;
  }
  if (!url.pathname.startsWith(SPIEL)) return;
  ereignis.respondWith(antworte(anfrage, url, false));
});
