{ ... }:
{
  perSystem =
    { ... }:
    {
      pre-commit = {
        check.enable = true;
        settings = {
          hooks = {
            eclint.enable = false;
            rustfmt.enable = true;
            nixpkgs-fmt.enable = true;
          };
        };
      };
    };
}
