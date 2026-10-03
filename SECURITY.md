# Security

This app creates and decrypts the keys that control a Vorka vault, so bugs here
matter as much as bugs in the contracts.

## Status

Not audited by a third party yet. An AI-assisted review covered the keystore
handling and signing code, and its findings were fixed. The review is in
[vorka-contracts](https://github.com/mathiaspellegrin/vorka-contracts/blob/master/docs/CODEX_SECURITY_REVIEW.md).

## Reporting a vulnerability

Please don't open a public issue. Email mathias.pellegrin.pro@gmail.com with
what you found, where, and how to reproduce it. I'll reply within 72 hours.

## What this app is built to resist

- Malware looking for plain-text keys or seed phrases: keys are only stored
  encrypted (scrypt and AES keystores) and decrypted in memory for one signing.
- Offline password guessing on a copied keystore: strong passwords are
  enforced and the key derivation is deliberately slow.
- Phishing through websites: there is no "connect to any dApp" flow. The app
  only builds calls from a vetted list of actions.

What it can't fix: a computer that's already compromised at the moment you
sign. More on this in the
[design notes](https://github.com/mathiaspellegrin/vorka-contracts/blob/master/docs/DESIGN.md).
