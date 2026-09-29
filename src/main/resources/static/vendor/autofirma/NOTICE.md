# Third-party component: AutoScript (Cliente @firma / AutoFirma)

- **Component**: `autoscript.js` -- the official JavaScript integration library for AutoFirma, published by the
  Spanish government's Cliente @firma project.
- **Version**: 1.10.1 (`AutoScript.VERSION`, verified in the downloaded file itself).
- **Source**: https://github.com/ctt-gob-es/clienteafirma, path
  `afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js`, branch `master`.
- **Retrieved**: 2026-09-28.
- **Git blob SHA-1** (of `autoscript.js` as downloaded): `dc9401987c4cd6834cefbb68ec1adee038557f5b`
  (verified with `git hash-object`, matching the SHA of that same path in the upstream repository).
- **Size**: 255151 bytes (verified with `wc -c`, matching the upstream `Content-Length`).
- **Licenses**: dual-licensed **GPL-2.0** and **EUPL-1.1**, at the licensee's choice (see `LICENSE.txt`, the
  component's own license notice, plus the full license texts `gpl-2.0.txt` and `EUPL-v1.1.pdf`, both copied
  unmodified from the same upstream repository, path `license/`).
- **Status in this project**: `autoscript.js` is included **unmodified** as a separate third-party component; it
  is loaded as an independent `<script>` file and used only through its public JavaScript API
  (`AutoScript.cargarAppAfirma`, `AutoScript.sign`, `SupportDialog.enableSupportDialog`). It is never patched,
  minified, inlined into another file, or bundled into this project's own GPL-3.0-licensed source. See
  `README.md` ("Componentes de terceros") for the full reasoning behind treating this as a reasoned aggregation
  of a separately-licensed component next to a GPL-3.0 project, rather than a derivative work -- that section is
  explicitly **not** a legal opinion.
