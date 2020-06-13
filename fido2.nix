{ mkDerivation, aeson, aeson-qq, base, base64-bytestring, binary
, bytestring, cborg, containers, cryptonite, http-types, scientific
, scotty, serialise, stdenv, tasty, tasty-hunit, text
, unordered-containers, uuid, vector, wai, wai-middleware-static
, warp, x509
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
    aeson aeson-qq base base64-bytestring bytestring cryptonite
    http-types scotty text uuid wai wai-middleware-static warp
  ];
  testHaskellDepends = [ base tasty tasty-hunit ];
  license = "unknown";
  hydraPlatforms = stdenv.lib.platforms.none;
}
