# SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

{
  lib,
  stdenv,
  callPackage,
  zig_0_16,
}:
let
  # Generated from build.zig.zon by zon2nix; regenerate with
  #   nix develop -c zon2nix --16 --nix=build.zig.zon.nix build.zig.zon
  zigDeps = callPackage ./build.zig.zon.nix { };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "scram-sha-256";
  version = "0.0.0";

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./build.zig
      ./build.zig.zon
      ./src
      ./completions
    ];
  };

  nativeBuildInputs = [ zig_0_16 ];

  # --system does not merely offer the directory, it forbids fetching: a
  # dependency missing from the farm is a build error naming the package
  # rather than a network attempt that fails somewhere less legible.
  zigBuildFlags = [
    "--system"
    "${zigDeps}"
  ];
  # The check phase assembles its own flags rather than reusing the build's,
  # so without this `zig build test` runs without --system, tries to fetch,
  # and fails in the sandbox.
  zigCheckFlags = finalAttrs.zigBuildFlags;

  doCheck = true;

  meta = {
    description = "Compute PostgreSQL SCRAM-SHA-256 password verifiers in Zig";
    homepage = "https://codeberg.org/jcollie/zig-scram-sha-256";
    license = lib.licenses.mit;
    mainProgram = "scram-sha-256";
    platforms = lib.platforms.all;
  };
})
