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
