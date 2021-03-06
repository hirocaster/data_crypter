defmodule DataCrypter.Mixfile do
  use Mix.Project

  def project do
    [app: :data_crypter,
     version: "0.1.0",
     elixir: "~> 1.3",
     description: "AES 128/256 GCM encrypt/decrypt wrapper for Elixir.",
     package: package(),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [{:ex_doc, "~> 0.18.0", only: :dev, runtime: false},
     {:credo, "~> 0.10.0", only: [:dev, :test], runtime: false}]
  end

  defp package do
    [ name: :data_crypter,
      files: ["lib", "mix.exs", "README*"],
      maintainers: ["hirocaster"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/hirocaster/data_crypter"} ]
  end
end
