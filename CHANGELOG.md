# Change Log

All notable changes will be documented in this file.

Check [Keep a Changelog](http://keepachangelog.com/) for recommendations on how to structure this file.

## Unreleased
 - TBD

## [3.0.1]
 - Added `GuardianSigner` as an extension to `UserSigner`
 - Given the fact that starting with [elrond-sdk-erdjs - v11.0.0](https://github.com/ElrondNetwork/elrond-sdk-erdjs/releases/tag/v11.0.0) the sender field is mandatory when constructing a transaction, `signedBy` is not needed on `applySignature()` anymore
 - Breaking change: breaks older erdjs which does not have `applyGuardianSignature` on transactions

## [2.1.0]
 - Implemented X25519 encryption, now `PubkeyDecryptor` and `PubkeyEncryptor` components are available

## [2.0.0]
 - Switched to MIT license

## [1.0.0]
 - Extracted `walletcore` and `crypto` packages from `erdjs`.
