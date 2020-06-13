# File which provides a callback taking an argument haskellPackages and
# selecting all the required packages for building the library.
haskellPackages:
  with haskellPackages;
    [
      aeson
      aeson-qq
      base64-bytestring
      binary
      bytestring
      cborg
      containers
      cryptonite
      http-types
      scientific
      scotty
      serialise
      stm
      tasty
      tasty-hunit
      text
      unordered-containers
      uuid
      vector
      wai
      wai-middleware-static
      warp
      x509
    ]
