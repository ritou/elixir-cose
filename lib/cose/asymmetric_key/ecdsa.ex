defmodule COSE.AsymmetricKey.ECDSA do
  @moduledoc """
  Key handling module for ECDSA

  ```
  iex(1)> key_map = %{
  ...(1)>   "crv" => "P-256",
  ...(1)>   "d" => "bBOCdlrsU1jxF3M9KBwce9w5iE0EpFoebGfIWLwgbBk",
  ...(1)>   "kty" => "EC2",
  ...(1)>   "x" => "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
  ...(1)>   "y" => "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k"
  ...(1)> }
  %{
    "crv" => "P-256",
    "d" => "bBOCdlrsU1jxF3M9KBwce9w5iE0EpFoebGfIWLwgbBk",
    "kty" => "EC2",
    "x" => "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
    "y" => "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k"
  }
  iex(2)> COSE.AsymmetricKey.ECDSA.from_map(key_map, encode: :base64url)
  {:ECPrivateKey, 1,
   <<108, 19, 130, 118, 90, 236, 83, 88, 241, 23, 115, 61, 40, 28, 28, 123, 220,
     57, 136, 77, 4, 164, 90, 30, 108, 103, 200, 88, 188, 32, 108, 25>>,
   {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
   <<4, 20, 51, 41, 204, 231, 134, 142, 65, 105, 39, 89, 156, 246, 90, 52, 243,
     206, 47, 253, 165, 90, 126, 202, 105, 237, 137, 25, 163, 148, 212, 47, 15,
     96, 247, 241, 167, 128, 216, 167, 131, 191, 183, 162, 221, ...>>}

  iex(3)> key_map = %{
  ...(3)>   "crv" => "P-256",
  ...(3)>   "kty" => "EC2",
  ...(3)>   "x" => "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
  ...(3)>   "y" => "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k"
  ...(3)> }
  %{
    "crv" => "P-256",
    "kty" => "EC2",
    "x" => "FDMpzOeGjkFpJ1mc9lo0884v_aVafspp7YkZo5TULw8",
    "y" => "YPfxp4DYp4O_t6LdayeW6BKNu87509Fo25Uplxo257k"
  }
  iex(4)> COSE.AsymmetricKey.ECDSA.from_map(key_map, encode: :base64url)
  {{:ECPoint,
    <<4, 20, 51, 41, 204, 231, 134, 142, 65, 105, 39, 89, 156, 246, 90, 52, 243,
      206, 47, 253, 165, 90, 126, 202, 105, 237, 137, 25, 163, 148, 212, 47, 15,
      96, 247, 241, 167, 128, 216, 167, 131, 191, 183, 162, 221, 107, 39, ...>>},
   {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}
  """

  require Logger

  @supported_curves ["P-256", "P-384", "P-512"]

  # TODO: don't return nil and do error handling

  # Public Key and Private Key with raw binary
  def from_map(key_map = %{"kty" => "EC2", "crv" => crv}) when crv in @supported_curves do
    try do
      key_map
      |> Enum.into(%{}, fn {k, v} ->
        if k in ["crv", "kty"] do
          {k, v}
        else
          {k, v |> Base.url_encode64(padding: false)}
        end
      end)
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.url_encode64/2 raised error. #{inspect(e)}")
        nil
    end
  end

  def from_map(_), do: nil

  # Public Key and Private Key with Base16 Encoding
  def from_map(key_map = %{"kty" => "EC2", "crv" => crv}, encode: :base16)
      when crv in @supported_curves do
    try do
      key_map
      |> Enum.into(%{}, fn {k, v} ->
        if k in ["crv", "kty"] do
          {k, v}
        else
          {k, v |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false)}
        end
      end)
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.decode16!/2 or Base.url_encode64/2 raised error. #{inspect(e)}")
        nil
    end
  end

  # Public Key and Private Key with Base64 URL Encoding
  def from_map(key_map = %{"kty" => "EC2", "crv" => crv}, encode: :base64url)
      when crv in @supported_curves do
    with %JOSE.JWK{kty: {:jose_jwk_kty_ec, ec_key}} <-
           JOSE.JWK.from_map(key_map |> Map.put("kty", "EC")) do
      ec_key
    else
      e ->
        Logger.debug("JOSE.JWK.from_map/1 raised error. #{inspect(e)}")
        nil
    end
  end

  def from_map(_, _), do: nil
end
