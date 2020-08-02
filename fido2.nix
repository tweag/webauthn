{ mkDerivation, aeson, aeson-qq, asn1-encoding, base
, base64-bytestring, binary, bytestring, cborg, cborg-json
, containers, cookie, cryptonite, directory, filepath, hspec
, http-types, memory, mtl, QuickCheck, quickcheck-instances
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
    containers cryptonite memory QuickCheck scientific serialise text
    unordered-containers vector x509
  ];
  executableHaskellDepends = [
    aeson aeson-qq base base64-bytestring bytestring cborg containers
    cookie cryptonite http-types mtl scotty serialise sqlite-simple stm
    text transformers uuid wai wai-middleware-static warp
  ];
  testHaskellDepends = [
    aeson asn1-encoding base bytestring cborg cborg-json cryptonite
    directory filepath hspec memory QuickCheck quickcheck-instances
    serialise text
  ];
  license = "unknown";
  hydraPlatforms = stdenv.lib.platforms.none;
}
