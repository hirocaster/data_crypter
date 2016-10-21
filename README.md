# DataCrypter

**AES 128/256 GCM encrypt/decrypt wrapper for Elixir.**

## Installation

  1. Add `data_crypter` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:data_crypter, "~> 0.1.0"}]
    end
    ```

  2. Ensure `data_crypter` is started before your application:

    ```elixir
    def application do
      [applications: [:data_crypter]]
    end
    ```
