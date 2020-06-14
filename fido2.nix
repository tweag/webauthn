{ mkDerivation, aeson, aeson-qq, base, base64-bytestring, binary
, bytestring, cborg, containers, cookie, cryptonite, directory
, filepath, hspec, http-types, mtl, scientific, scotty, serialise
, stdenv, stm, text, transformers, unordered-containers, uuid
, vector, wai, wai-middleware-static, warp, x509
}:
mkDerivation {
  pname = "fido2";
  version = "0.1.0.0";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson base base64-bytestring binary bytestring cborg containers
    cryptonite scientific serialise text unordered-containers vector
    x509
  ];
  executableHaskellDepends = [
    aeson aeson-qq base base64-bytestring bytestring containers cookie
    cryptonite http-types mtl scotty stm text transformers uuid wai
    wai-middleware-static warp
  ];
  testHaskellDepends = [
    aeson base bytestring directory filepath hspec
  ];
  license = "unknown";
  hydraPlatforms = stdenv.lib.platforms.none;
}
