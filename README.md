# vorka-cli

The desktop app and CLI for [Vorka](https://www.vorka.net). It creates your
keys, encrypts them onto two USB drives, and signs and sends transactions for
your vault. The contracts it talks to are in
[vorka-contracts](https://github.com/mathiaspellegrin/vorka-contracts).

> **Not audited.** See [SECURITY.md](SECURITY.md) before using it with real
> funds.

## How it works

- Two USB drives. The primary drive holds only the everyday key. The recovery
  drive holds only the fallback key and stays unplugged.
- Keys are standard encrypted keystores (scrypt and AES, the same format as
  ethers and geth). They're only decrypted in memory, for one signature.
- No password is cached. You type it each time.
- No backend is required. RPC URL, chain ID, vault address and factory address
  are stored locally.

Why it's built this way is explained in the
[design notes](https://github.com/mathiaspellegrin/vorka-contracts/blob/master/docs/DESIGN.md).

## Setup

```
npm install
npm run build
```

## Desktop app

On a provisioned drive, customers launch `VORKA.exe`. It opens a native
Electron window (no browser, local server or Node.js install needed), detects
the two drives and walks through setup. It can create the vault, show its
state, withdraw to the owner, freeze the vault and recover the primary key.

Windows comes first, macOS next, Linux later.

In this local-only build, the signing key also pays gas, so its address needs
some native currency.

## CLI

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

Commands that send a transaction need `VORKA_BROADCASTER_KEY`, set to the
private key of a funded account. That account only pays gas on the selected
chain (`--chain`, default `conflux-mainnet`, see `src/chain.ts`). It is never
the vault's operational or fallback key.

## Tests

```
npm test
```

`test/domain.test.ts` matters most. It checks that this app's EIP-712 encoding
matches exactly what the contracts verify on-chain. If it fails after a
contract change, fix `src/domain.ts` first.

## Building the Windows app

```
npm run package:windows
```

This builds a portable Windows executable in `release/`. The GitHub workflow in
`.github/workflows/build.yml` builds it on Windows and signs it when the code
signing certificate is configured.

## License

[MIT](LICENSE)
