{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      ...
    }:
    let
      inherit (pkgs.stdenv) isDarwin;
    in
    {
      rust-project = {
        src = lib.cleanSource inputs.self;

        crates = {
          "authn_kit" = {
            crane = {
              args = {
                # `rustls` pulls in `aws-lc-sys`, which builds C and needs cmake
                # plus a compiler at build time.
                nativeBuildInputs = with pkgs; [
                  pkg-config
                  cmake
                ];
                buildInputs =
                  lib.optionals isDarwin [
                    pkgs.libiconv
                    pkgs.fixDarwinDylibNames
                  ]
                  ++ [
                    pkgs.openssl
                  ];
                # The default feature set is deliberately empty, so a bare build
                # would exercise almost nothing. Build what a consumer actually
                # uses.
                cargoExtraArgs = "--features actix,axum,full";
              };
              extraBuildArgs = {
                # https://discourse.nixos.org/t/how-to-use-install-name-tool-on-darwin/9931/2
                postInstall = ''
                  ${if isDarwin then "fixDarwinDylibNames" else ""}
                '';
              };
            };
          };
        };
      };
    };
}
