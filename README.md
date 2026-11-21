# device-sync

Secure device-to-device data sync for offline-first web apps: a signed, gapless change log per
device, end-to-end encrypted transfer (files, envelopes, sessions), device trust and invitation, a
client for a simple message relay, and Web Push helpers. The package is app-independent: record
shapes, merge rules on a business level, rights, texts and UI belong to your app.

**Status: scaffold (0.0.0).** Nothing is implemented or exported yet; the package is built layer by
layer and is not published to npm. See [docs/architecture.md](docs/architecture.md) for the planned
layers.

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
