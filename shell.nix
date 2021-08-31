(import ./default.nix).shellFor {
  tools = {
    cabal = "3.4.0.0";
    hlint = "latest";
    haskell-language-server = "latest";
  };
}
