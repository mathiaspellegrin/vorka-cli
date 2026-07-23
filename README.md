# vorka-cli

The customer-facing companion app: keystore generation, EIP-712 signing, and
broadcasting for `VorkaVault`. This is what ships on a sold drive — see
`docs/VORKA.md` at the repo root for the full design (key custody model,
why `execute()` has no allowlist, the curated action registry, etc.).

This package will eventually be its own private repo. `../provisioning/`
depends on this package's build output (`dist/`) to flash drives before
sale — build this one first.

## Setup

```
npm install
npm run build
```

## Commands

```
node dist/cli.js generate                                    # create your own keys
node dist/cli.js backup <destination>                        # copy the encrypted keystores elsewhere
node dist/cli.js create-vault <factoryAddress>
node dist/cli.js withdraw <vaultAddress> <token> <amount>
node dist/cli.js list-actions
node dist/cli.js execute <vaultAddress> <actionId> <argsJson>
node dist/cli.js rotate-auth <vaultAddress> <newAuthAddress>
node dist/cli.js rotate-fallback <vaultAddress> <newFallbackAddress>
```

`VORKA_BROADCASTER_KEY` must be set to a funded account's private key before
any command that broadcasts a transaction — it only pays Conflux gas, it's
never the vault's `authAddress`/`fallbackAddress`.

## Tests

```
npm test
```

`test/domain.test.ts` is the one that matters most: it cross-checks this
package's EIP-712 encoding against the exact formula `VorkaVaultBase`/`VorkaVault`
use on-chain. If it fails after a contract change, the typehashes have drifted
out of sync — fix `src/domain.ts` before anything else.
