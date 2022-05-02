defmodule Ueberauth.Strategy.WorkOS do
  @moduledoc """
  WorkOS Strategy for Überauth.
  """

  # Disable Überauth's built in CSRF-protection as it prevents WorkOS's
  # IdP-initiated flow from completing
  use Ueberauth.Strategy, ignores_csrf_attack: true

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles initial request for WorkOS authentication.
  """
  def handle_request!(conn) do
    params =
      [:connection, :organization, :provider, :login_hint]
      |> Enum.reduce([], fn key, params ->
        params
        |> with_optional(key, conn)
        |> with_param(key, conn)
      end)
      |> with_state_param(conn)

    opts = [redirect_uri: callback_url(conn)]
    redirect!(conn, Ueberauth.Strategy.WorkOS.OAuth.authorize_url!(params, opts))
  end

  @doc """
  Handles the callback from WorkOS.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]

    case Ueberauth.Strategy.WorkOS.OAuth.get_access_token(params) do
      {:ok, token} ->
        conn
        |> put_private(:workos_token, token)
        |> put_private(:workos_user, token.other_params["profile"])

      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:workos_user, nil)
    |> put_private(:workos_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    conn.private.workos_user["id"]
  end

  @doc """
  Includes the credentials from the WorkOS response.
  """
  def credentials(conn) do
    token = conn.private.workos_token

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.workos_user

    %Info{
      email: user["email"],
      first_name: user["first_name"],
      last_name: user["last_name"],
      name: user["first_name"] <> " " <> user["last_name"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the WorkOS callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.workos_token,
        user: conn.private.workos_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
