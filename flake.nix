{
  inputs = {
    # Need Rust 1.80+, switch to 24.11 after release cut.
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
        inherit (pkgs) lib;
        fs = lib.fileset;
      in
      {
        packages = rec {
          default = ssh-idp;

          ssh-idp = pkgs.rustPlatform.buildRustPackage {
            pname = "ssh-idp";
            version = "0.1.0";

            src = fs.toSource {
              root = ./.;
              fileset = fs.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./src
              ];
            };
            cargoLock = {
              lockFile = ./Cargo.lock;
              outputHashes = {
                "jsonwebtoken-9.3.0" = "sha256-ZDdT3JW9mABZDBTkzMaHml1VbZryIJDsuoEz1vSDRhE=";
              };
            };

            meta = {
              mainProgram = "ssh-idp";
            };
          };

          docker = pkgs.dockerTools.buildLayeredImage {
            name = "ssh-idp";
            tag = "latest";
            config = {
              Entrypoint = [ (lib.getExe ssh-idp) ];
            };
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
