{ pkgs, lib, config, inputs, ... }:

{
  # https://devenv.sh/basics/

  # https://devenv.sh/packages/
  packages = with pkgs; [ git wireproxy hyperfine samply ];

  # https://devenv.sh/scripts/
  # scripts.hello.exec = "echo hello from $GREET";
  # https://devenv.sh/services/
  languages.rust.enable = true;

  devcontainer.enable = true;
  
  # https://devenv.sh/languages/
  # languages.nix.enable = true;

  # https://devenv.sh/pre-commit-hooks/
  # pre-commit.hooks.shellcheck.enable = true;

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

    # See full reference at https://devenv.sh/reference/options/
}
