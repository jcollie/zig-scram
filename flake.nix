{
  inputs = {
    nixpkgs = {
      url = "nixpkgs/nixos-unstable";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };
  outputs = {
    nixpkgs,
    flake-utils,
    ...
  } @ inputs:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
      in {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.zig_0_13
          ];
          buildInputs = [
          ];
        };
      }
    );
}
