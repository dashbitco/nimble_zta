defmodule NimbleZTA.MixProject do
  use Mix.Project

  @version "0.1.1"
  @repo_url "https://github.com/dashbitco/nimble_zta"

  def project do
    [
      app: :nimble_zta,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Hex
      package: package(),
      description:
        "Add Zero Trust Authentication (ZTA) to web apps running in your private cloud",

      # Docs
      name: "NimbleZTA",
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {NimbleZTA.Application, []}
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.18"},
      {:req, "~> 0.5"},
      {:jose, "~> 1.11"},
      {:bandit, "~> 1.0", only: :test},
      {:ex_doc, ">= 0.0.0", only: :docs}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @repo_url,
        "Changelog" => "#{@repo_url}/blob/main/CHANGELOG.md"
      }
    ]
  end

  defp docs do
    [
      main: "NimbleZTA",
      source_ref: "v#{@version}",
      source_url: @repo_url
    ]
  end
end
