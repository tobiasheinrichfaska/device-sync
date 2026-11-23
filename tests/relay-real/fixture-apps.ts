// The apps of the conformance fixture in the real relay server's configuration format
// (konfiguration/apps.json, German member names). Used by the harness and by the plain start.
export function realAppsJson(fixture: any): string {
  return JSON.stringify({
    apps: Object.fromEntries(
      Object.entries<any>(fixture.apps).map(([name, a]) => [
        name,
        {
          name: `App ${name}`,
          herkuenfte: a.origins,
          nachweisSchluessel: a.proofKey ? [fixture.proofKeys[a.proofKey].publicRaw] : [],
          einladen: a.invitations,
          gesperrt: a.blockedDevices ?? [],
          mandanten: a.groups,
          streng: a.strictGroups ?? [],
        },
      ]),
    ),
  });
}
