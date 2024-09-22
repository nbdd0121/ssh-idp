{
  inputs = {
    # Need newer Rust, switch to 24.11 after release cut.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "ssh-idp";
          version = "0.1.0";

          src = ./.;
          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "jsonwebtoken-9.3.0" = "sha256-ZDdT3JW9mABZDBTkzMaHml1VbZryIJDsuoEz1vSDRhE=";
              "pageant-0.0.1-beta.3" = "sha256-EC7yGPUIVlN2N++IchAvbtaWK+x9kV9v7oUhElw2WZY=";
            };
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
