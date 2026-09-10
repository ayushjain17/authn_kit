{
  # `om ci run` builds every flake output and runs the checks, which is what the
  # nix workflow invokes.
  flake.om.ci.default = {
    root = {
      dir = ".";
    };
  };
}
