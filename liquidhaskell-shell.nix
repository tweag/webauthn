{pkgs ? import (fetchTarball "https://github.com/tweag/nixpkgs/archive/e544ee88fa4590df75e221e645a03fe157a99e5b.tar.gz") {}}:

with pkgs;

mkShell {
  LANG="C.UTF-8";

  buildInputs = [
    cabal-install
    cacert
    entr
    fd
    git
    glibcLocales
    haskell.compiler.ghc8107
    jq
    less
    nodejs
    python310
    yarn
    zlib
    z3
  ];

}
