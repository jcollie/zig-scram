# SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

{
  description = "SCRAM (RFC 5802 / RFC 7677) in Zig, including PostgreSQL password verifiers";

  inputs = {
    nixpkgs = {
      url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    };
    zon2nix = {
      url = "github:jcollie/zon2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      zon2nix,
      ...
    }:

    let
      inherit (nixpkgs) lib;
      makePackages =
        system:
        import nixpkgs {
          inherit system;
        };
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        rec {
          scram-sha-256 = pkgs.callPackage ./package.nix { };
          default = scram-sha-256;

          # The dependency farm on its own, for a job that runs `zig build`
          # for something other than the package:
          #   zig build --system "$(nix build --print-out-paths .#zig-deps)"
          zig-deps = pkgs.callPackage ./build.zig.zon.nix { };
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        {
          default = pkgs.mkShell {
            name = "zig-scram";
            nativeBuildInputs = [
              pkgs.zig_0_16
              pkgs.reuse

              # zon2nix shells out to `zig env`, and prints "unable to execute
              # zig, is it in your PATH?" and writes nothing if it cannot find
              # one -- which leaves the previous build.zig.zon.nix in place
              # looking untouched. Wrapping it pins the Zig it finds to the one
              # this project builds with rather than whatever the caller has.
              (pkgs.symlinkJoin {
                name = "zon2nix";
                paths = [ zon2nix.packages.${system}.zon2nix ];
                nativeBuildInputs = [ pkgs.makeWrapper ];
                postBuild = ''
                  wrapProgram $out/bin/zon2nix \
                    --prefix PATH : ${lib.makeBinPath [ pkgs.zig_0_16 ]}
                '';
              })
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.kcov
              pkgs.perf
            ];
          };
        }
      );
    };
}
