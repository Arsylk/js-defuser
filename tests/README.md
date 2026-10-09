# Engine regression tests

```sh
npm test            # fixtures, obfuscated corpora, structural primitives, logger, catalog
npm run test:gates  # whole-program release gates through the built CLI
```

Every test compares the execution of the original and the recovered program in
isolated Node VM contexts: recovery must parse, report no pass errors, and print
the same things. `fixtures/` holds 29 small semantics programs; `obfuscated/`
holds those programs transformed by javascript-obfuscator 4.2.2 (eight
configurations, seed 1234) and by js-confuser 2.1.3 (one configuration per
transform, plus the `low`, `medium` and `locks` presets). The js-confuser cases
must additionally come back without any of the obfuscator's generated names.

`obfuscated/self-defending.js` is a hand-built program in the shape of
javascript-obfuscator's `selfDefending` + base64 string-array output (decoder
sentinel and call-controller probe that inspect their own source text). It is
not regenerated; every line after its header comment must stay unbroken.

`gates/` holds two programs at js-confuser's maximum settings (high preset +
pack + integrity + selfDefending + tamperProtection): the obfuscator's own
editor demo and the `21-bitwise` fixture. `gates.test.ts` runs them through
`dist/cli.js` and asserts the output is the source program again.

The JSON fixtures record the exact generator options. To regenerate, supply an
installed obfuscator package directory; the tests themselves need no obfuscator
package and no network:

```sh
node tests/regenerate-fixtures.cjs /path/to/javascript-obfuscator      # 4.2.2
node tests/regenerate-jsconfuser-fixtures.cjs /path/to/js-confuser    # 2.1.3
```

These are behavioural regression checks, not a proof that arbitrary JavaScript
is safe to transform. Function/source reflection and modified built-ins require
particular care when extending the passes.
