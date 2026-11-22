// Starts the REAL relay server (its own source, read from the directory in RELAY_REAL_PATH, never
// modified) for the opt-in tests of this package. Opt-in: `npm run test:relay-real`.
//
// The real server has no test interface of its own. This harness is the test interface from the
// protocol document ("Test interface"): it builds the real server from the real modules with an
// injected clock, injected limits and a stand-in for the push service, exactly the knobs the real
// code offers through its `Umgebung`, and it adds a tiny control port. Everything else (HTTP layer,
// checks, tokens, limits) is the real code. It is configured from the fixture of the conformance
// cases. It prints one line of JSON, `{"relay":PORT,"control":PORT}`, when it is ready.
//
// Not part of `npm test` or CI: it needs the other repository on disk and a Node that strips types.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { realAppsJson } from './fixture-apps.ts';
import { loadCore, loadModule } from './real-source.ts';

const root = process.env['RELAY_REAL_PATH'];
if (!root) throw new Error('RELAY_REAL_PATH is not set');
const [{ serverAnlegen }, { appsLesen, entwicklerLesen }, { GRENZEN }, zulassung, core] =
  await Promise.all([
    loadModule(root, 'http'),
    loadModule(root, 'konfiguration'),
    loadModule(root, 'grenzen'),
    loadModule(root, 'zulassung'),
    loadCore(root),
  ]);

const fixture = JSON.parse(
  readFileSync(
    process.env['RELAY_REAL_CASES'] ?? new URL('../relay/conformance/cases.json', import.meta.url),
    'utf8',
  ),
).fixture;

// The developer's public key and passwords of revision 2 (the real server holds scrypt hashes of the passwords).
const entwickler = entwicklerLesen(
  fixture.developerKeys?.main?.publicRaw,
  fixture.developerPasswords
    ? JSON.stringify(
        fixture.developerPasswords.map((p: any) => ({
          app: p.app,
          mandant: p.group,
          hash: zulassung.passwortHash(p.password),
          bis: p.until,
          hoechstens: p.max,
          auchMitGeraeten: p.alsoWithDevices === true,
        })),
      )
    : undefined,
);

const appsText = realAppsJson(fixture);
const apps = appsLesen(appsText);
const schluessel = Buffer.from(fixture.secrets.main, 'base64url');

// The document's limit names, in the real server's names.
const LIMIT_NAMES: Record<string, string> = {
  waitMs: 'wartezeitMs',
  presenceMs: 'anwesendMs',
  maxContentBytes: 'nachrichtBytes',
  minMessageWeight: 'nachrichtMindestBytes',
  maxRecipients: 'empfaengerJeAblegen',
  maxPresenceAsk: 'anwesendFragen',
  collectBytes: 'abholenBytes',
  mailboxMessages: 'jeEmpfaengerAnzahl',
  mailboxBytes: 'jeEmpfaengerBytes',
  senderBytes: 'jeAbsenderBytes',
  appBytes: 'jeAppBytes',
  totalBytes: 'gesamtBytes',
  requestsPerMinute: 'anfragenJeMinute',
  ringPerHour: 'klingelnJeStunde',
  invitePerHour: 'einladenJeStunde',
  enrolProofPerHour: 'einschreibenJeStunde',
  enrolInvitePerHour: 'einschreibenEinladungJeStunde',
  devicesPerApp: 'geraeteJeMandant',
  devicesTotal: 'geraeteGesamt',
  blocksPerHour: 'sperrenJeStunde',
  blocklistPerGroup: 'sperrlisteJeMandant',
  passwordTriesPerHour: 'passwortVersucheJeStunde',
};

let offsetMs = 0;
// The limits object the real code reads. Byte limits are read at every use, so they are changed in
// place and the state stays (as the document says); the rate counters are sized when the relay is
// built, so changing one of those builds a fresh relay (state lost: the cases set them first).
let limits: Record<string, number> = { ...GRENZEN };
const COUNTERS = new Set([
  'anfragenJeMinute',
  'klingelnJeStunde',
  'einladenJeStunde',
  'einschreibenJeStunde',
  'einschreibenEinladungJeStunde',
  'sperrenJeStunde',
  'passwortVersucheJeStunde',
]);
let pushResult: number | 'unreachable' = 201;
const pushes: unknown[] = [];

const now = (): number => Date.now() + offsetMs;
const clock = (): number => performance.now() + offsetMs;

const build = (): any =>
  core.create({
    schluessel,
    apps,
    entwickler,
    jetzt: now,
    takt: clock,
    stand: 'a'.repeat(40),
    grenzen: limits,
    senden: async (a: unknown) => {
      pushes.push(a);
      if (pushResult === 'unreachable') throw new Error('unreachable');
      return pushResult;
    },
  });

let current = build();
// The HTTP layer of the real server keeps one relay object; this forwards to the current one so
// that `reset` and `setLimits` can replace it without a restart.
const forward: any = new Proxy(
  {},
  {
    get:
      (_t, k) =>
      (...a: unknown[]) =>
        current[k](...a),
  },
);
const server = serverAnlegen(forward);
const timer = setInterval(() => current.aufraeumen(), 1000);
timer.unref();

const control = createServer((req, res) => {
  const parts: Buffer[] = [];
  req.on('data', (c) => parts.push(c));
  req.on('end', () => {
    let out: unknown = { ok: true };
    try {
      const b = JSON.parse(Buffer.concat(parts).toString('utf8') || '{}');
      if (b.op === 'reset') {
        offsetMs = 0;
        limits = { ...GRENZEN };
        pushResult = 201;
        pushes.length = 0;
        current = build();
      } else if (b.op === 'advanceTime') {
        offsetMs += Number(b.ms);
      } else if (b.op === 'setLimits') {
        let rebuild = false;
        for (const [k, v] of Object.entries<number>(b.limits)) {
          const real = LIMIT_NAMES[k];
          if (!real) throw new Error(`limit ${k} has no counterpart in the real server`);
          limits[real] = v;
          if (COUNTERS.has(real)) rebuild = true;
        }
        if (rebuild) current = build();
      } else if (b.op === 'setPushResult') {
        pushResult = b.result;
      } else if (b.op === 'pushes') {
        out = { pushes };
      } else if (b.op === 'now') {
        out = { now: now() };
      } else throw new Error('unknown op');
      res.writeHead(200).end(JSON.stringify(out));
    } catch (e) {
      res.writeHead(400).end(JSON.stringify({ error: String(e) }));
    }
  });
});

await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
await new Promise<void>((ok) => control.listen(0, '127.0.0.1', ok));
const port = (s: { address(): any }): number => s.address().port;
console.log(JSON.stringify({ relay: port(server), control: port(control) }));
process.on('SIGTERM', () => process.exit(0));
