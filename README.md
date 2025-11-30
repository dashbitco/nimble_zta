# NimbleZTA

Add [Zero Trust](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview) Authentication (ZTA) to your Plug/Phoenix web apps. In a nutshell, if you are running applications inside your private cloud, you can use your cloud provider to identify and control access to your app, so you can focus on your application logic.

`nimble_zta` is a collection of strategies for different providers. CloudFlare, Google Cloud Platform, and Tailscale are currently supported, with additional HTTP Basic Auth and Pass Through strategies available for development and testing. [Read the docs for more information](https://hexdocs.pm/nimble_zta).

[This library was extracted from Livebook](https://livebook.dev/).

## Installation

You can install `nimble_zta` by adding it to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:nimble_zta, "~> 0.1"}
  ]
end
```

## Nimble*

All nimble libraries by Dashbit:

  * [NimbleCSV](https://github.com/dashbitco/nimble_csv) - simple and fast CSV parsing
  * [NimbleOptions](https://github.com/dashbitco/nimble_options) - tiny library for validating and documenting high-level options
  * [NimbleOwnership](https://github.com/dashbitco/nimble_ownership) - resource ownership tracking
  * [NimbleParsec](https://github.com/dashbitco/nimble_parsec) - simple and fast parser combinators
  * [NimblePool](https://github.com/dashbitco/nimble_pool) - tiny resource-pool implementation
  * [NimblePublisher](https://github.com/dashbitco/nimble_publisher) - a minimal filesystem-based publishing engine with Markdown support and code highlighting
  * [NimbleTOTP](https://github.com/dashbitco/nimble_totp) - tiny library for generating time-based one time passwords (TOTP)
  * [NimbleZTA](https://github.com/dashbitco/nimble_zta) - add Zero Trust Authentication (ZTA) to web apps running in your private cloud

## License

Copyright 2025 Dashbit

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
