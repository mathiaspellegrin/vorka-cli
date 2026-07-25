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

`build:portable` creates a single executable for the current operating system in
`release/`. Build releases on each target OS with an official, statically linked
Node distribution; distro builds that link `libnode` dynamically cannot be used
as a Node SEA base binary.

`test/domain.test.ts` is the one that matters most: it cross-checks this
package's EIP-712 encoding against the exact formula `VorkaVaultBase`/`VorkaVault`
use on-chain. If it fails after a contract change, the typehashes have drifted
out of sync — fix `src/domain.ts` before anything else.

## End-to-end smoke test

```
./scripts/e2e-smoke.sh
```

Starts a local Anvil devnet, deploys `VorkaVault`/`VorkaVaultFactory` for
real, then runs `scripts/e2e-smoke.ts` through a full create-vault → fund →
withdraw → rotate-auth flow against that deployment, asserting on-chain
state after each step. Proves the contracts and this package's keystore/
signing/chain code genuinely interoperate — unit tests alone don't catch
that. Uses `--chain local` (`src/chain.ts`'s `CHAINS.local`, Anvil's default
`127.0.0.1:8545`/chain id `31337`).
