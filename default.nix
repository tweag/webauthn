{ isShell ? false, system ? builtins.currentSystem }:
let
  # Read in the Niv sources
  sources = import ./nix/sources.nix { };

  pkgs = import sources.nixpkgs {
    overlays = [ ];
    config = { };
    inherit system;
  };

  inherit (pkgs) lib;
  inherit (import sources."gitignore.nix" { inherit lib; }) gitignoreSource;

  src = gitignoreSource ./.;

  # Keep this in sync with the `tested-with` field in `webauthn.cabal`
  expectedGhcVersion = "8.10.7";

  hpkgs_aeson1 = pkgs.haskellPackages.extend
    (hself: hsuper: {
      ghc =
        if hsuper.ghc.version != expectedGhcVersion then
          throw
            ("We expect the default nixpkgs GHC version to be ${expectedGhcVersion}, "
              + "but it is ${hsuper.ghc.version} instead. Update the `expectedGhcVersion` "
              + "variable in `default.nix` and update the `tested-with` field in "
              + "`webauthn.cabal` at the same time.")
        else hsuper.ghc;

      webauthn = pkgs.haskell.lib.disableLibraryProfiling
        (hself.callCabal2nix "webauthn" src { });

      server = hself.callCabal2nix "server" (src + "/server") { };

      jose = hself.callHackage "jose" "0.8.5" { };

      base64-bytestring = hself.base64-bytestring_1_2_1_0;

      x509-validation = hself.callHackageDirect
        {
          pkg = "x509-validation";
          ver = "1.6.12";
          sha256 = "1jrsryn6hfdmr1b1alpj5zxvw26dw8y7kqpq555q2njm3kvwmxap";
        }
        { };

        aeson-schemas = pkgs.haskell.lib.appendPatch (pkgs.haskell.lib.unmarkBroken hsuper.aeson-schemas)
          (pkgs.writeText "dont-test-compile-time-errors.patch" ''
            diff --git a/test/Tests/GetQQ.hs b/test/Tests/GetQQ.hs
            index c030e53..236ba3f 100644
            --- a/test/Tests/GetQQ.hs
            +++ b/test/Tests/GetQQ.hs
            @@ -50,7 +50,7 @@ test =
                 "`get` quasiquoter"
                 [ testValidExpressions
                 , testInvalidExpressions
            -    , testCompileTimeErrors
            +    --, testCompileTimeErrors
                 ]
             
             testValidExpressions :: TestTree
          '');
    });

  hpkgs = hpkgs_aeson1.extend (hself: hsuper: {

    jose = hself.jose_0_9;

    aeson = hself.aeson_2_0_3_0;

    OneTuple = hself.OneTuple_0_3_1;

    hashable = hself.hashable_1_4_0_1;

    quickcheck-instances = hself.quickcheck-instances_0_3_27;

    text-short = pkgs.haskell.lib.dontCheck hself.text-short_0_1_5;

    semialign = hself.semialign_1_2_0_1;

    hspec-expectations-json = pkgs.haskell.lib.dontCheck hself.hspec-expectations-json_1_0_0_5;

    attoparsec = hself.attoparsec_0_14_3;

    time-compat = hself.time-compat_1_9_6_1;

    # Needed for aeson 2.0
    http2 = pkgs.haskell.lib.appendPatch hsuper.http2 (pkgs.fetchpatch {
      url = "https://github.com/kazu-yamamoto/http2/commit/0a1f64cb7cd2042554cd2d4e96da850a8940f08d.patch";
      sha256 = "0kbbd7dv49m6slcfw61kzy21v4d2ingnbygg4i3spn91v3dyh87y";
    });
  });

  deploy = pkgs.writeShellScriptBin "deploy" ''
    ${pkgs.nixos-rebuild}/bin/nixos-rebuild switch --build-host localhost --target-host webauthn.dev.tweag.io \
      --use-remote-sudo --no-build-nix \
      -I nixpkgs=${toString sources.nixpkgs} \
      -I nixos-config=${toString infra/configuration.nix}
  '';

  shell = hpkgs.shellFor {
    packages = p: [ p.webauthn p.server ];
    withHoogle = true;
    nativeBuildInputs = [
      pkgs.haskellPackages.cabal-install
      pkgs.haskellPackages.haskell-language-server
      pkgs.haskellPackages.hlint
      pkgs.haskellPackages.ormolu

      pkgs.entr
      pkgs.gitMinimal
      pkgs.niv
      pkgs.python3
      pkgs.yarn
      pkgs.nodejs
      pkgs.jq

      deploy
    ];
    shellHook = ''
      export NIX_PATH=nixpkgs=${toString sources.nixpkgs}
    '';
  };

in
if isShell then shell else {
  webauthn_aeson1 = hpkgs_aeson1.webauthn;
  inherit (hpkgs) webauthn server;
  inherit pkgs hpkgs;
}
