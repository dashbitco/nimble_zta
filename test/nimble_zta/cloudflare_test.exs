defmodule NimbleZTA.CloudflareTest do
  use ExUnit.Case, async: true
  import Plug.Test
  import Plug.Conn

  alias NimbleZTA.Cloudflare

  @fields [:id, :name, :email]
  @name Context.Test.Cloudflare

  def router(conn, _opts) do
    case conn.request_path do
      "/certs" -> json_key(conn, nil)
      "/user_identity" -> valid_user_identity(conn, nil)
    end
  end

  def json_key(conn, _) do
    key = %{
      "kty" => "RSA",
      "e" => "AQAB",
      "use" => "sig",
      "kid" => "bmlyt6y2uWrgWeUh3mENiSkEOR7Np3I8swSjlK98iX0",
      "alg" => "RS256",
      "n" =>
        "rKACsPICtiNC5V3IGvTatP6aaqyxjhKvAr5LXzUsMyqUBI3FjzuTvL8xfmc_uw2WIh6ltQfhxEEFrQygnmgmk4eM6xTI2j-O3hgcQ4FBAoiii3IlVRV-bjZWTI5uQe7nkjML8ruGKjPovCP-tcbAEKKrzd9DnKdxlyOmFVrrEQvJ_rSssdy_ugl79LHZD0sG9d6y77mfQHQ3W9zrcvC5P8rHzYuMB6DmZZn2SHVgb4WRqblXqnOQG70xGM70Zfr4Y2jRl0tabIvTBQqiQBFDdPZSB4I1Cz74GlBWYftFzJITFtAatbfyrzieS__ctDmP_PLT_o544zKHrQK2uNSJvw"
    }

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, JSON.encode!(%{keys: [key]}))
  end

  def valid_user_identity(conn, _) do
    expected_user = %{
      "user_uuid" => "1234567890",
      "name" => "Tuka Peralta",
      "email" => "tuka@peralta.com"
    }

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, JSON.encode!(expected_user))
  end

  def router_with_invalid_key(conn, _opts) do
    case conn.request_path do
      "/certs" ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(200, JSON.encode!(%{keys: ["invalid_key"]}))

      "/user_identity" ->
        valid_user_identity(conn, nil)
    end
  end

  def router_with_forbidden_user(conn, _opts) do
    case conn.request_path do
      "/certs" ->
        json_key(conn, nil)

      "/user_identity" ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(403, "")
    end
  end

  def router_with_service_token_auth(conn, _opts) do
    case conn.request_path do
      "/certs" ->
        json_key(conn, nil)

      "/user_identity" ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(400, JSON.encode!(%{"err" => "could not retrieve identity"}))
    end
  end

  @moduletag bypass: &__MODULE__.router/2
  setup {TestHelper, :bypass}

  @identity_based_signed_jwt "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJsaXZlYm9va3dlYiIsImVtYWlsIjoidHVrYUBwZXJhbHRhLmNvbSIsImlhdCI6MTUxNjIzOTAyMiwiaXNzIjoibGl2ZWJvb2siLCJzdWIiOiIxMjM0NTY3ODkwIn0.C-Z-pYBL2QStyHkfxLHdbgqM4xG9XqLLQjZh5McUoDgo9P6ZhPoNTtwkr-n9LxN-9Ds509d3KCAJnzudECyVroqsCwRf57ksfktbLfi87twbNob94lByYizszHpjxniHCp8NjrTLfsOhuZq7GTK5-lsTEccUqh_q1lew2Mjbm6gFp4_PAcKQ3nVwU2OYybPjV2G3JCIeBk9aXRheEW1vBcAwXwIEHgB0S2LEN1zOs1pOmiOneAFkrJy872UuUOxEjDvMcHQYq7SEzaKyq2ypcwLJPs8r9qBa2inaVvXvxiKf3DzORSI7SvafA2oILzQesOpSdWHf0c-V3Mt7SKNCcQ"

  @service_token_based_signed_jwt "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjM0NTY3ODkwIiwiY29tbW9uX25hbWUiOiJjbGllbnRfaWQuYWNjZXNzIiwiZXhwIjoxNTE2MjM5MDIyLCJpYXQiOjE1MTYyMzkwMjIsImlzcyI6ImxpdmVib29rIiwic3ViIjoiIiwidHlwZSI6ImFwcCJ9.HYb6jwm_sHmvX8AnGAm0nQTLs9rjlaRE-X905Ns5FotnVMZcsxifeESH_d-fske_trdLp1HFi3GivxXZepzJqITKcA3749aig363wL2viQ4P2-_fNgzc1122F-5YgobhxV23Y_Ic_ncgiFtQFJeDcF0A8TN_nVMWPc4Jer7RWqC1jAuDrA7UUMtKEbLAQbS5-ZmdPrnkQMKgb93rc4B_yxn7aX10jh5L2d3FbdC-vqX6m4gpgeZMJJkNyCHBzxK67DgeIO6HZM3VCjOLX-DLWsDxfNIRZW64rXdwL333k7LCTKOB4Js2e5B2eS4yjAP5IGAknU2YvwXVTRwTFp8AuQ"

  setup context do
    token = Map.get(context, :token, @identity_based_signed_jwt)

    options = [
      name: @name,
      custom_identity: %{
        iss: "livebook",
        key: "livebookweb",
        certs: "http://localhost:#{context.port}/certs",
        user_identity: "http://localhost:#{context.port}/user_identity"
      }
    ]

    conn = conn(:get, "/") |> put_req_header("cf-access-jwt-assertion", token)
    {:ok, token: token, options: options, conn: conn}
  end

  test "returns the user_identity when the user is valid", %{options: options, conn: conn} do
    start_supervised!({Cloudflare, options})
    {_conn, user} = Cloudflare.authenticate(@name, conn, fields: @fields)

    assert %{
             id: "1234567890",
             email: "tuka@peralta.com",
             name: "Tuka Peralta",
             strategy: "user_identity",
             payload: %{}
           } =
             user
  end

  @tag bypass: &__MODULE__.router_with_forbidden_user/2
  test "returns nil when the user_identity fails", %{options: options, conn: conn} do
    start_supervised!({Cloudflare, options})
    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  test "returns nil when the iss is invalid", %{options: options, conn: conn} do
    invalid_identity = Map.replace(options[:custom_identity], :iss, "invalid_iss")
    options = Keyword.put(options, :custom_identity, invalid_identity)
    start_supervised!({Cloudflare, options})

    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  test "returns nil when the token is invalid", %{options: options} do
    conn = conn(:get, "/") |> put_req_header("cf-access-jwt-assertion", "invalid_token")
    start_supervised!({Cloudflare, options})

    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  test "returns nil when the assertion is invalid", %{options: options, token: token} do
    conn = conn(:get, "/") |> put_req_header("invalid_assertion", token)
    start_supervised!({Cloudflare, options})

    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  @tag bypass: &__MODULE__.router_with_invalid_key/2
  test "returns nil when the key is invalid", %{options: options, conn: conn} do
    start_supervised!({Cloudflare, options})
    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  @tag token: @service_token_based_signed_jwt,
       bypass: &__MODULE__.router_with_service_token_auth/2
  test "returns the JWT fields when the service token is valid", %{options: options, conn: conn} do
    start_supervised!({Cloudflare, options})
    assert {_conn, metadata} = Cloudflare.authenticate(@name, conn)
    assert %{client_id: "client_id.access", strategy: "service_token", payload: %{}} = metadata
  end

  @tag token: @service_token_based_signed_jwt,
       bypass: &__MODULE__.router_with_service_token_auth/2
  test "returns nil when the service token is invalid", %{options: options} do
    conn = conn(:get, "/") |> put_req_header("cf-access-jwt-assertion", "invalid_token")
    start_supervised!({Cloudflare, options})
    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end

  @tag token: @service_token_based_signed_jwt,
       bypass: &__MODULE__.router_with_service_token_auth/2
  test "returns nil when the `iss` mismatches", %{options: options, conn: conn} do
    invalid_identity = Map.replace(options[:custom_identity], :iss, "invalid_iss")
    options = Keyword.put(options, :custom_identity, invalid_identity)
    start_supervised!({Cloudflare, options})
    assert {_conn, nil} = Cloudflare.authenticate(@name, conn, fields: @fields)
  end
end
