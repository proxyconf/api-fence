{
  description = "Envoy OpenAPI Filter - Dynamic Module built with Rust";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self
    , nixpkgs
    , rust-overlay
    , flake-utils
    }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use stable Rust toolchain with necessary components
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
        };

        # Build inputs for compiling the dynamic module
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
          clang
          llvmPackages.libclang.lib
        ];

        # Runtime dependencies
        buildInputs = with pkgs; [
          openssl
          zlib
        ];

      in
      {
        # Development shell
        devShells.default = pkgs.mkShell {
          inherit buildInputs nativeBuildInputs;

          packages = with pkgs; [
            # Formatters and linters
            nixpkgs-fmt
            rustfmt
            clippy

            # Development tools
            cargo-watch
            cargo-edit
            cargo-outdated
            bacon

            # Envoy and testing tools
            # NOTE: Use envoy-bin (not envoy) - it's the pre-built binary package
            # we currently use a global envoy exec (a 1.38.0 pre version) found in $PATH
            #envoy-bin
            jq
            curl

            # Documentation
            mdbook
          ];

          shellHook = ''
            echo "🦀 Envoy OpenAPI Filter Development Environment"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
            echo "Envoy version: $(envoy --version 2>&1 | head -n1)"
            echo ""
            echo "📦 Available commands:"
            echo "  cargo build --release    - Build the dynamic module"
            echo "  cargo test               - Run unit tests"
            echo "  cargo clippy             - Run linter"
            echo "  cargo watch -x test      - Watch and run tests"
            echo "  bacon                    - Interactive test runner"
            echo ""

            # Set up Rust environment variables
            export RUST_BACKTRACE=1
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"

            # Point bindgen to the Nix store libclang (critical for building Envoy SDK)
            export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"

            # Ensure cargo cache is writable
            export CARGO_HOME="$PWD/.cargo"
            mkdir -p .cargo
          '';
        };

        # Formatter for nix files
        formatter = pkgs.nixpkgs-fmt;
      });
}
