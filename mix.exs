defmodule Cose.MixProject do
  use Mix.Project

  def project do
    [
      app: :cose,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :jose]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
      {:jose, "~> 1.8"},

      # Erlang CBOR library
      {:cbor, github: "yjh0502/cbor-erlang"}
    ]
  end
end
