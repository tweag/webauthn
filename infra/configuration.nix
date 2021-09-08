{ modulesPath, lib, pkgs, ... }: {
  imports = [ "${modulesPath}/virtualisation/amazon-image.nix" ];
  ec2.hvm = true;

  nix = {
    autoOptimiseStore = true;
    nixPath = [
      "nixpkgs=${toString pkgs.path}"
    ];
    trustedUsers = [ "root" "@wheel" ];
    binaryCachePublicKeys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    binaryCaches = [
      "https://hydra.iohk.io"
    ];
  };

  environment.systemPackages = with pkgs; [
    git
    ripgrep
    jq
    htop
    direnv
    # For terminfo
    kitty
    nix-direnv
  ];

  environment.pathsToLink = [ "/share/nix-direnv" ];

  programs.bash.interactiveShellInit = ''
    eval "$(direnv hook bash)"
  '';

  programs.neovim = {
    enable = true;
    vimAlias = true;
    defaultEditor = true;
    configure = {
      customRC = ''
        filetype on
        syntax enable
        filetype plugin indent on
        colorscheme gruvbox

        set tabstop=2
        set shiftwidth=2
        set hidden
        set termguicolors
        set showcmd
        set background=dark
        set mouse=a
        set undolevels=10000
        set undofile
        set nobackup
        set nowritebackup
        set number
        set expandtab

        " Copy to local clipboard
        autocmd TextYankPost * if v:event.operator is 'y' && v:event.regname is ''' | OSCYankReg " | endif
      '';
      packages.myVimPackage = with pkgs.vimPlugins; {
        start = [
          vim-nix
          editorconfig-vim
          gruvbox-community
          vim-oscyank
        ];
      };
    };
  };

  security.sudo.wheelNeedsPassword = false;

  users.users.infinisil = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHjY4cuUk4IWgBgnEJSULkIHO+njUmIFP+WSWy7IobBs infinisil@vario"
    ];
  };

  users.users.erin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    openssh.authorizedKeys.keys = [
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCg6ReK4TnqMW3dz1Ir/gM9OpoZzHnxDfKJH9020pdwE253eS06tIAKTGauiEa8dJfzy272mHmha8Y797CCW1ofezO58TF/wc+gxN7Ev8ho4ULX8ciV0osg9O5LdajcYyblDZjuTUhG/YcmvfIqKLPyMINue9xMm3Jdg6ROthyaEKlEJQO/kbwIe00VYkM5hFrItl6leBr5cH/BritmexKn+kfhcxYVgSIPhSJQxJpD5b32V8B2An07eOBuUjXxQVuKKZrFpWmcnLkmGxkBfBCWMFdTcBHpVBHP9god25O89/t6yr+igVZxIy7AYnFcRPhAypaZ1X5pzqIauV4n2cdQ+C+2RF6sFepSzbQpD9CKz9+gsIU8IqsmImZN1Vl9g2+2UBx4J6YaIXf53zJg7y2gv5HrELgMZRNrrYvF1Jq9oTHOE4jKMZhcKdJS18OG5jBqA8D/muLWl9K5Q/sUz7N2t+m5RnEXqzJLxnljfopKaPoRvjoXG30zVOuyUVWEENRDQ/TMccUAiRYjkfCbYh1frwEUW5lR++E38QRqIgycOxHQRIM+tdbdydLan3tCm9trGXi3CZMAgvsYaWX6itOIDPbpGBP7+K1MhYchzzTWPO1SaksxhuQQxQQsax1FAbhzaa08OJVyVAWrohpEBxMcXC0YhVSuXVmvIIPT0tTMtw=="
    ];
  };

  security.acme.acceptTerms = true;
  security.acme.email = "silvan.mosberger@tweag.io";

  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    virtualHosts = {
      "webauthn.dev.tweag.io" = {
        enableACME = true;
        forceSSL = true;
        locations."/".proxyPass = "http://localhost:8080";
      };
    # Proxies <attr>.webauthn.dev.tweag.io to localhost:<port>
    } // lib.mapAttrs' (name: value: lib.nameValuePair "${name}.webauthn.dev.tweag.io" {
      enableACME = true;
      forceSSL = true;
      locations."/".proxyPass = "http://localhost:${toString value}";
    }) (lib.importJSON ./subdomains.json);
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];

}
