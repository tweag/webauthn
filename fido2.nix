{ mkDerivation, aeson, aeson-qq, asn1-encoding, base
, base64-bytestring, binary, bytestring, cborg, containers, cookie
, cryptonite, directory, filepath, hspec, http-types, memory, mtl
, scientific, scotty, serialise, sqlite-simple, stdenv, stm, text
, transformers, unordered-containers, uuid, vector, wai
, wai-middleware-static, warp, x509
}:
mkDerivation {
  pname = "fido2";
  version = "0.1.0.0";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson asn1-encoding base base64-bytestring binary bytestring cborg
    containers cryptonite memory scientific serialise text
    unordered-containers vector x509
  ];
  executableHaskellDepends = [
    aeson aeson-qq base base64-bytestring binary bytestring containers
    cookie cryptonite http-types mtl scotty sqlite-simple stm text
    transformers uuid wai wai-middleware-static warp
  ];
  testHaskellDepends = [
    aeson base bytestring directory filepath hspec
  ];
  license = "unknown";
  hydraPlatforms = stdenv.lib.platforms.none;
}
