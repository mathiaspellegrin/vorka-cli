# vorka-cli

The customer-facing companion app: keystore generation, EIP-712 signing, and
broadcasting for `VorkaVault`. This is what ships on a sold drive — see
`docs/VORKA.md` in the [`vorka-docs`](https://github.com/Fluxpad/vorka-docs) repo for
the full design (key custody model, why `execute()` has no allowlist, the
curated action registry, etc.).

Split out of the `vorka` monorepo. [`vorka-provisioning`](https://github.com/Fluxpad/vorka-provisioning)
depends on this package's build output via a pinned git dependency to flash
drives before sale — build and tag this one first when cutting a release.

## Setup

```
npm install
npm run build
```

## Commands

For customers, launch `VORKA.exe` from either USB. The Windows-first client
opens in its own native Electron window—no browser, localhost server, Node.js
installation, or browser extension is involved. It detects the provisioned
drives and creates a split signed bundle: the primary USB receives only the
operational keystore and the recovery USB receives only the fallback keystore.
The app also provides local RPC settings, Vault creation/state, native
withdrawal to the beneficiary, emergency freeze, and primary-device recovery.
macOS comes next and Linux later.

Vorka Core does not require a Vorka backend. In this local-only build, the
primary or recovery signer also pays transaction gas, so the corresponding
address must hold enough native currency. RPC URL, chain ID, Vault address and
factory address are saved only in the local Electron profile.

The CLI remains the open-source/manual interface:

```
node dist/cli.js generate                                    # create your own keys
node dist/cli.js backup <destination>                        # copy the encrypted keystores elsewhere
node dist/cli.js create-vault <factoryAddress> <beneficiaryAddress>
node dist/cli.js withdraw <vaultAddress> <token> <amount>
node dist/cli.js list-actions
node dist/cli.js execute <vaultAddress> <actionId> <argsJson>
node dist/cli.js freeze <vaultAddress>
node dist/cli.js rotate-auth <vaultAddress> <newAuthAddress>
node dist/cli.js rotate-fallback <vaultAddress> <newFallbackAddress>
```

`VORKA_BROADCASTER_KEY` must be set to a funded account's private key before
any command that broadcasts a transaction — it only pays gas on the active
chain (`--chain`, default `conflux-mainnet` — see `src/chain.ts`'s `CHAINS`),
it's never the vault's `authAddress`/`fallbackAddress`.

## Tests

```
npm test
npm run build:portable
```

`npm run package:windows` builds the native Electron client as a portable
Windows executable in `release/`. `build:portable` remains temporarily available
for the old SEA setup while the migration is being completed.

The workflow `.github/workflows/build.yml` now builds Windows only. When the
Authenticode certificate secrets are configured it signs and verifies the
portable executable before upload.

`test/domain.test.ts` is the one that matters most: it cross-checks this
package's EIP-712 encoding against the exact formula `VorkaVaultBase`/`VorkaVault`
use on-chain. If it fails after a contract change, the typehashes have drifted
out of sync — fix `src/domain.ts` before anything else.

## End-to-end smoke test

Moved to the [`vorka-docs`](https://github.com/Fluxpad/vorka-docs) hub repo's
`scripts/e2e-smoke.sh` — it needs both `vorka-contracts` (for `forge`) and
this repo cloned as sibling directories, so it can't live inside either
one alone.
