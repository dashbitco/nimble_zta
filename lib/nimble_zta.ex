defmodule NimbleZTA do
  @moduledoc """
  Enable Zero Trust Authentication within your Plug/Phoenix application,
  mostly geared towards internal applications.

  The following ZTA providers are supported:

    * `NimbleZTA.Cloudflare`
    * `NimbleZTA.GoogleIAP`
    * `NimbleZTA.Tailscale`

  We also support the following providers for dev/test/staging:

    * `NimbleZTA.BasicAuth` - HTTP basic authentication with a single user-pass
    * `NimbleZTA.PassThrough` - always succeeds with no metadata

  ## Usage

  First you must add the ZTA provider of your choice to your supervision tree:

      {NimbleZTA.GoogleIAP, name: :google_iap, identity_key: "foobar"}

  where the `identity_key` is the identity provider specific key. See their
  specific docs for more information.

  Then you can use the provider's `c:authenticate/3` callback to authenticate
  users on every request:

      plug :zta

      def zta(conn, _opts) do
        case NimbleZTA.GoogleIAP.authenticate(conn, :google_iap) do
          # The provider is redirecting somewhere for follow up
          {%{halted: true} = conn, nil} ->
            conn

          # Authentication failed
          {%{halted: false} = conn, nil} ->
            send_resp(conn, 401, "Unauthorized")

          # Authentication succeeded
          {conn, metadata} ->
            put_session(conn, :user_metadata, metadata)
        end
      end

  Each provider may have specific options supported on `authenticate/3`.
  """

  @type name :: atom()

  @type access_type :: :full | :apps

  @typedoc """
  A metadata of keys returned by zero-trust authentication provider.

  The following keys are supported:

    * `:id` - a string that uniquely identifies the user
    * `:name` - the user name
    * `:email` - the user email
    * `:avatar_url` - the user avatar
    * `:groups` - the user groups
    * `:payload` - the provider payload

  Note that none of the keys are required. The metadata returned depends
  on the provider.
  """
  @type metadata :: %{
          optional(:id) => String.t(),
          optional(:name) => String.t(),
          optional(:email) => String.t(),
          optional(:avatar_url) => String.t() | nil,
          optional(:groups) => list(map()),
          optional(:payload) => map()
        }

  @doc """
  Each provider must specify a child specification for its processes.

  The `:name` and `:identity_key` keys are expected.
  """
  @callback child_spec(name: name(), identity_key: String.t()) :: Supervisor.child_spec()

  @doc """
  Authenticates against the given name.

  It will return one of:

    * `{non_halted_conn, nil}` - the authentication failed and you must
      halt the connection and render the appropriate report

    * `{halted_conn, nil}` - the authentication failed and the connection
      was modified accordingly to request the credentials

    * `{non_halted_conn, metadata}` - the authentication succeed and the
      following metadata about the user is available

  """
  @callback authenticate(name(), Plug.Conn.t(), keyword()) :: {Plug.Conn.t(), metadata() | nil}

  @doc false
  def init do
    :ets.new(__MODULE__, [:named_table, :public, :set, read_concurrency: true])
  end

  @doc """
  Gets metadata about a ZTA of a given name.

  This API is mostly used by NimbleZTA implementations.
  """
  def get(name) do
    :ets.lookup_element(__MODULE__, name, 2)
  end

  @doc """
  Puts metadata about a ZTA of a given name.

  This API is mostly used by NimbleZTA implementations.
  """
  def put(name, value) do
    :ets.insert(__MODULE__, [{name, value}])
  end
end
