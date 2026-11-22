# device-sync

Secure device-to-device data sync for offline-first web apps: a signed, gapless change log per
device, end-to-end encrypted transfer (files, envelopes, sessions), device trust and invitation, a
client for a simple message relay, and Web Push helpers. The package is app-independent: record
shapes, merge rules on a business level, rights, texts and UI belong to your app.

> **Not security-reviewed by a human — do not use for real data.** Four adversarial AI review rounds have been run; the latest still found high-severity availability and consistency issues, which are being fixed. The end-to-end session and the encrypted file are new and have had no review round yet.

**Status: work in progress (0.0.0).** Implemented and exported so far: the `core` layer (canonical
JSON, check values, device keys, signatures, end-to-end session, encrypted file), the `log` layer (change log, merge, signing and judging,
the exchange protocol with strict parsers and partial sessions) and the `trust` layer (device list,
derived trust, meeting code, invitation). Not yet there: envelope, relay client,
push, transfer, browser. The package is not published to npm. See
[docs/architecture.md](docs/architecture.md) for the layers.

## Install and test

```bash
npm install
npm test
npm run typecheck
```

Bug reports and ideas: [GitHub Issues](https://github.com/tobiasheinrichfaska/device-sync/issues).

## License

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This project is licensed under the **GNU Affero General Public License v3.0** (AGPLv3).
You are free to use, modify, and distribute this software under the terms of the AGPLv3.
If you use this software to provide a network service, you must make the full source code
of your modifications available to users of that service.

**Commercial License:** If you wish to use this software in a closed-source or proprietary
product, a commercial license is available. Contact: tobias.a.w.heinrich@gmail.com

See [LICENSE](LICENSE) for the full AGPLv3 text.
See [LICENSE_COMMERCIAL.md](LICENSE_COMMERCIAL.md) for commercial licensing terms.
