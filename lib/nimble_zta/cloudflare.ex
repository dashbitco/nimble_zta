defmodule NimbleZTA.Cloudflare do
  @moduledoc """
  Use Cloudflare for Zero Trust Authentication.

  Add it to your supervision tree as:

      {NimbleZTA.Cloudflare, name: MyApp.ZTA, identity_key: "your-team-name"}

  And then call `NimbleZTA.Cloudflare.authenticate(MyApp.ZTA, conn)` in the
  Plug you want to enable this authentication.

  The identity key is your team name. For more details about how to find yours,
  see: https://developers.cloudflare.com/cloudflare-one/glossary/#team-name.

  Cloudflare supports two types of authentication:

    * User identity authentication - where the user is authenticated by Cloudflare
      and the provider returns the user metadata. This is the default authentication
      strategy.
      Reference: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/#identity-based-authentication

    * Service token authentication - where the provider returns a service token
      metadata with a `client_id` field instead of user metadata. This is used
      for machine-to-machine authentication.
      Reference: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/#service-token-authentication

  For more information about Cloudflare Zero Trust,
  see: https://developers.cloudflare.com/cloudflare-one/.
  """
  @behaviour NimbleZTA

  use GenServer
  require Logger
  import Plug.Conn

  @assertion "cf-access-jwt-assertion"
  @renew_after 24 * 60 * 60 * 1000
  @fields %{
    "user_uuid" => :id,
    "name" => :name,
    "email" => :email,
    "common_name" => :client_id,
    "strategy" => :strategy
  }
  @service_token_keys MapSet.new(["aud", "common_name", "exp", "iat", "iss", "sub", "type"])

  @doc false
  defstruct [:req_options, :identity, :name]

  @doc false
  def start_link(opts) do
    identity = opts[:custom_identity] || identity(opts[:identity_key])
    name = Keyword.fetch!(opts, :name)
    options = [req_options: [url: identity.certs], identity: identity, name: name]
    GenServer.start_link(__MODULE__, options, name: name)
  end

  @impl true
  def authenticate(name, conn, _opts \\ []) do
    token = get_req_header(conn, @assertion)
    {identity, keys} = NimbleZTA.get(name)
    {conn, authenticate_user(token, identity, keys)}
  end

  @impl true
  def init(options) do
    state = struct!(__MODULE__, options)
    {:ok, renew(state)}
  end

  @impl true
  def handle_info(:renew, state) do
    {:noreply, renew(state)}
  end

  defp renew(state) do
    Logger.debug("[#{inspect(__MODULE__)}] requesting #{inspect(state.req_options)}")
    keys = Req.request!(state.req_options).body["keys"]
    Process.send_after(self(), :renew, @renew_after)
    NimbleZTA.put(state.name, {state.identity, keys})
    state
  end

  defp authenticate_user(token, identity, keys) do
    with [encoded_token] <- token,
         {:ok, token} <- verify_token(encoded_token, keys),
         :ok <- verify_iss(token, identity.iss),
         {:ok, metadata} <- get_metadata(token, encoded_token, identity.user_identity) do
      for({k, v} <- metadata, new_k = @fields[k], do: {new_k, v}, into: %{payload: metadata})
    else
      _ -> nil
    end
  end

  defp verify_token(token, keys) do
    Enum.find_value(keys, :error, fn key ->
      case JOSE.JWT.verify(key, token) do
        {true, token, _s} -> {:ok, token}
        _ -> nil
      end
    end)
  end

  defp verify_iss(%{fields: %{"iss" => iss}}, iss), do: :ok
  defp verify_iss(_, _), do: :error

  defp get_metadata(token, encoded_token, url) do
    if MapSet.equal?(MapSet.new(Map.keys(token.fields)), @service_token_keys) do
      {:ok, Map.put(token.fields, "strategy", "service_token")}
    else
      cookie = "CF_Authorization=#{encoded_token}"
      resp = Req.request!(url: url, headers: [cookie: cookie])

      if resp.status == 200,
        do: {:ok, Map.put(resp.body, "strategy", "user_identity")},
        else: :error
    end
  end

  defp identity(key) do
    %{
      key: key,
      key_type: "domain",
      iss: "https://#{key}.cloudflareaccess.com",
      certs: "https://#{key}.cloudflareaccess.com/cdn-cgi/access/certs",
      assertion: "cf-access-jwt-assertion",
      email: "cf-access-authenticated-user-email",
      user_identity: "https://#{key}.cloudflareaccess.com/cdn-cgi/access/get-identity"
    }
  end
end
