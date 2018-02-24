defmodule COSE.AsymmetricKey.ECDSA do

  require Logger

  @supported_curves ["P-256", "P-384", "P-512"]

  # TODO: don't return nil and do error handling

  # Private Key
  # NOTE: d, x, y are binary
  def from_map(
    %{"kty" => "EC",
      "crv" => crv,
      "d" => d,
      "x" => x,
      "y" => y}
  ) when crv in @supported_curves do
    try do
      %{"kty" => "EC",
        "crv" => crv,
        "d" => d |> Base.url_encode64(padding: false),
        "x" => x |> Base.url_encode64(padding: false),
        "y" => y |> Base.url_encode64(padding: false)}
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.url_encode64/2 raised error. #{inspect e}")
        nil
    end
  end
  # Public Key
  # NOTE: x, y are binary
  def from_map(
    %{"kty" => "EC",
      "crv" => crv,
      "x" => x,
      "y" => y}
  ) when crv in @supported_curves do
    try do
      %{"kty" => "EC",
        "crv" => crv,
        "x" => x |> Base.url_encode64(padding: false),
        "y" => y |> Base.url_encode64(padding: false)}
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.url_encode64/2 raised error. #{inspect e}")
        nil
    end
  end
  def from_map(_), do: nil

  # Private Key
  # NOTE: d, x, y are encoded with Base16
  def from_map(
    %{"kty" => "EC",
      "crv" => crv,
      "d" => d,
      "x" => x,
      "y" => y},
    encode: :base16
  ) when crv in @supported_curves do
    try do
      %{"kty" => "EC",
        "crv" => crv,
        "d" => d |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false),
        "x" => x |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false),
        "y" => y |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false)}
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.decode16!/2 or Base.url_encode64/2 raised error. #{inspect e}")
        nil
    end
  end
  # Public Key
  # NOTE: x, y are encoded with Base16
  def from_map(
    %{"kty" => "EC",
      "crv" => crv,
      "x" => x,
      "y" => y},
    encode: :base16
  ) when crv in @supported_curves do
    try do
      %{"kty" => "EC",
        "crv" => crv,
        "x" => x |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false),
        "y" => y |> Base.decode16!(case: :lower) |> Base.url_encode64(padding: false)}
      |> from_map(encode: :base64url)
    rescue
      e ->
        Logger.debug("Base.decode16!/2 or Base.url_encode64/2 raised error. #{inspect e}")
        nil
    end
  end

  # Public Key and Private Key with Base64 URL Encoding
  def from_map(key_map =
    %{"kty" => "EC",
      "crv" => crv,
      "x" => _,
      "y" => _},
    encode: :base64url
  ) when crv in @supported_curves do
    with %JOSE.JWK{kty: {:jose_jwk_kty_ec, ec_key}} <- JOSE.JWK.from_map(key_map) do
      ec_key
    else
      e ->
        Logger.debug("JOSE.JWK.from_map/1 raised error. #{inspect e}")
        nil
    end
  end
  def from_map(_, _), do: nil
end
