### next version

* Support the
  [`transports`](https://www.w3.org/TR/webauthn-2/#dom-authenticatorattestationresponse-transports-slot)
  field, allowing servers to store information from the browser on how
  authenticators were communicated with (e.g. internal, NFC, etc.). When users
  log in, this information can then be passed along in [Credential
  Descriptors](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor),
  ensuring that only the transports initially registered as supported by the
  authenticator may be used. This is recommended by the standard.
