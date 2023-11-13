### Next release: 0.9.0.0

* [#182](https://github.com/tweag/webauthn/pull/182) Migrate to the crypton library ecosystem.
  crypton is a hard fork of cryptonite, which was no longer maintained.
  Minimum version bounds have been bumped accordingly.
* Restore GHC 8.8 compatibility.

### 0.8.0.0

* [#178](https://github.com/tweag/webauthn/pull/178) Remove orphan instance for ToJSON ByteString.
  Use newtypes for the binary data including the PNG icons for authenticators and the cryptographic values.

### 0.7.0.0

* [#174](https://github.com/tweag/webauthn/pull/174) Correctly verify packed
  attestation when the AAGUID extension of the certitificate is missing. This is
  a backwards-incompatible change for packed attestation responses that
  previously failed due to the missing AAGUID extension. These responses now
  succeed.

### 0.6.0.1

* [#167](https://github.com/tweag/webauthn/pull/167) Fix missing file from sdist for testing

### 0.6.0.0

* [#162](https://github.com/tweag/webauthn/pull/162) Enable MDS blob parsing to handle invalid entries without completely failing to parse
* [#163](https://github.com/tweag/webauthn/pull/163) Fix build with mtl-2.3

### 0.5.0.1

* [#159](https://github.com/tweag/webauthn/pull/159) Allow mtl-2.3.1 and support GHC 9.4

### 0.5.0.0

* [#157](https://github.com/tweag/webauthn/pull/157) Add support for the [credProps](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-credential-properties-extension) extension
* [#158](https://github.com/tweag/webauthn/pull/158) Update root certificates

### 0.4.1.2
* [#155](https://github.com/tweag/webauthn/pull/155) Increase cabal bounds for aeson and monad-time to support latest versions from Hackage

### 0.4.1.1
* [#153](https://github.com/tweag/webauthn/pull/153) Increase cabal bounds to support up to GHC 9.2

### 0.4.1.0

* [#148](https://github.com/tweag/webauthn/pull/148) Allow authentication on Safari even though it violates the specification with an empty user handle
* [#149](https://github.com/tweag/webauthn/pull/149) Export constructors for `Crypto.WebAuthn.Encoding.WebAuthnJson` types and derive `FromJSON` for all of them
* [#151](https://github.com/tweag/webauthn/pull/151) Fix decoding of packed attestations without a `x5c` CBOR key. This fixes attestation on MacBook Pros with Chrome and TouchID.

### 0.4.0.0

* [#129](https://github.com/tweag/webauthn/pull/129) Rename and expand
  documentation for authentication/registration errors.
* [#136](https://github.com/tweag/webauthn/pull/136) Improve the safety and
  remove duplication of the public key interface. More checks are being done
  now, preventing invalid public keys from being constructed.
* [#140](https://github.com/tweag/webauthn/pull/140) Introduction of new
  serialization-related modules, all reexported via `Crypto.WebAuthn`:
  - `Crypto.WebAuthn.Model.Defaults` for defaults of optional fields
  - `Crypto.WebAuthn.Encoding.Strings` for string serializations of enumerations
  - `Crypto.WebAuthn.Encoding.Binary` for binary serializations
* [#140](https://github.com/tweag/webauthn/pull/140) Backwards-incompatible
  changes/fixes regarding serialization:
  - Fix unknown `AuthenticatorTransport` values being ignored. This breaks
    backwards compatibility when the received `AuthenticatorTransport`s are
    inspected and stored in the database. Users are encouraged to serialize
    individual `AuthenticatorTransport`s to strings using the new
    `encodeAuthenticatorTransport`. The [example
    server](https://github.com/tweag/webauthn/tree/master/server) has been
    updated to store all encoded `AuthenticatorTransport`s as a CBOR-encoded
    bytestring in the database, but other schemes to store multiple transports
    can also be employed.
  - Rename webauthn-json decoding/encoding functions to have a "wj" prefix like
    `wjEncodeCredentialOptionsRegistration`. The types they interact with have
    changed their prefix from `IDL` to `WJ` as well
  - Introduce `wjDecodeCredentialRegistration'` (with a tick) to take a
    `SupportedAttestationStatementFormats` argument, while the unticked version
    doesn't take such an argument anymore. In the future only the unticked
    version is expected to stay backwards-compatible.
  - `ccdCrossOrigin`s type was corrected from `Bool` to `Maybe Bool`, where
    `Nothing` has the same semantics as `Just False`. This is necessary for
    compatibility with WebAuthn Level 1 clients, which don't set this field


### 0.3.0.0

* [#125](https://github.com/tweag/webauthn/pull/125) Some small metadata type
  simplifications involving `msUpv` and `SomeMetadataEntry`
* [#126](https://github.com/tweag/webauthn/pull/126) Decrease lower bounds of
  many dependencies including `base`, adding compatibility with GHC 8.8

### 0.2.0.0

* [#115](https://github.com/tweag/webauthn/pull/115) Increase the upper bound
  of the supported Aeson versions, allowing the library to be built with Aeson
  2.0. Drop the deriving-aeson dependency.
* [#117](https://github.com/tweag/webauthn/pull/117) Rename and expand
  documentation for attestation statement format errors. Some unused errors
  were removed.

### 0.1.1.0

* [#111](https://github.com/tweag/webauthn/pull/111) Support the
  [`transports`](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot)
  field, allowing servers to store information from the browser on how
  authenticators were communicated with (e.g. internal, NFC, etc.). When users
  log in, this information can then be passed along in [Credential
  Descriptors](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor),
  ensuring that only the transports initially registered as supported by the
  authenticator may be used. This is recommended by the standard.
* [#112](https://github.com/tweag/webauthn/pull/112) Decrease lower bounds for
  aeson and unordered-containers.
