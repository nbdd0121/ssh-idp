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
                "pageant-0.0.1-beta.3" = "sha256-EC7yGPUIVlN2N++IchAvbtaWK+x9kV9v7oUhElw2WZY=";
              };
            };

            meta = {
              mainProgram = "ssh-idp";
            };
          };

          docker = pkgs.dockerTools.buildImage {
            name = "ssh-idp-docker";
            tag = "latest";
            copyToRoot = [
              (pkgs.runCommandLocal "" { } ''
                mkdir -p $out/work
              '')
            ];
            config = {
              Entrypoint = [ (lib.getExe ssh-idp) ];
              WorkingDir = "/work";
            };
          };
        };

        formatter = pkgs.nixfmt-rfc-style;
      }
    );
}
