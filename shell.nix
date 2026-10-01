let
  sources = import ./lon.nix;
  pkgs = (import sources.nixpkgs { });

  passthru = pkgs.pkgsCross.aarch64-multiplatform.m1n1.passthru;
  rustPlatform = passthru.rustPlatform;
  rustPackages = passthru.rustPackages;

  crosspkgs = pkgs.pkgsCross.aarch64-multiplatform;
in
crosspkgs.mkShell {
  nativeBuildInputs = [
    pkgs.imagemagick
    rustPackages.rustc
    rustPackages.cargo
    rustPlatform.cargoSetupHook
  ];

  shellHook = ''
    export ARCH=${crosspkgs.stdenv.cc.targetPrefix}
  '';

}

