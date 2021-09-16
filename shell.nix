let
  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/071317d543205ee5f5611d391a37582f9b282240.tar.gz";
    sha256 = "00s7lnwijrwssnn8ggmd66yqvix7j2p9w7my6ksyynfgf68yl7z0";
  };
  pkgs = import nixpkgs {
    overlays = [];
    config = {};
  };
in pkgs.mkShell {
  nativeBuildInputs = with pkgs.haskellPackages; [
    ghc
    cabal-install
    haskell-language-server
    stack
  ];
}
