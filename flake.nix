{
  description = "Framework- and protocol-agnostic authentication primitives for Rust web services";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    systems.url = "github:nix-systems/default";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-flake = {
      url = "github:juspay/rust-flake";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:

    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      imports = [
        inputs.rust-flake.flakeModules.default
        inputs.rust-flake.flakeModules.nixpkgs
        inputs.pre-commit-hooks.flakeModule
        ./nix/pre-commit.nix
        ./nix/rust.nix
        ./nix/om.nix
      ];

      perSystem =
        {
          pkgs,
          self',
          config,
          ...
        }:
        {
          formatter = pkgs.nixpkgs-fmt;

          devShells.default = pkgs.mkShell {
            inputsFrom = [
              self'.devShells.rust
              config.pre-commit.devShell
            ];
            packages = with pkgs; [
              gnumake
              nixpkgs-fmt
              # Release tooling: `cog bump` drives versioning, `cargo set-version`
              # is its pre-bump hook.
              cocogitto
              cargo-edit
              cargo-msrv
              bacon
              cargo-watch
            ];

            shellHook = ''
              # If it leaks in from the host system, it confuses the darwin linker.
              unset DEVELOPER_DIR
            '';
          };
        };
    };
}
