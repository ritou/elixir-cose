defmodule COSE.CWT.Claims do
  @moduledoc """
  functions for handling CWT Claims
  """

  alias COSE.CBOR

  @doc """
  Convert claims map into CBOR binary.
  Unregistered claims will be removed.

  TODO: Currently cti is treated as a string, but it must be treated as a byte string.

  ## Examples

    COSE.CWT.Claims.to_binary(%{
      "iss" => "coap://as.example.com",
      "sub" => "erikw",
      "aud" => "coap://light.example.com",
      "exp" => 1444064944,
      "nbf" => 1443944944,
      "iat" => 1443944944,
      "cti" => "\\vq"}) |> Base.encode16(case: :lower)
  """
  def to_binary(map) when is_map(map) do
    try do
      map
      |> Enum.filter(fn {k, _v} -> !is_nil(claim_name_to_key(k)) end)
      |> Enum.into(%{}, fn {k, v} -> {claim_name_to_key(k), v} end)
      |> CBOR.encode()
    rescue
      # TODO: return error
      _ ->
        nil
    end
  end

  def to_binary(_), do: nil

  def to_map(binary) when is_binary(binary) and binary != "" do
    try do
      binary
      |> CBOR.decode()
      |> Enum.filter(fn {k, _v} -> !is_nil(key_to_claim_name(k)) end)
      |> Enum.into(%{}, fn {k, v} -> {key_to_claim_name(k), v} end)
    rescue
      # TODO: return error
      _ ->
        nil
    end
  end

  def to_map(_), do: nil

  @registered_claims %{
    "iss" => 1,
    "sub" => 2,
    "aud" => 3,
    "exp" => 4,
    "nbf" => 5,
    "iat" => 6,
    "cti" => 7
  }
  @registered_keys @registered_claims |> Enum.into(%{}, fn {k, v} -> {v, k} end)

  defp claim_name_to_key(claim_name) when is_binary(claim_name) do
    @registered_claims[claim_name]
  end

  defp claim_name_to_key(_), do: nil
  def __claim_name_to_key__(claim_name), do: claim_name_to_key(claim_name)

  defp key_to_claim_name(key) when is_integer(key), do: @registered_keys[key]
  defp key_to_claim_name(_), do: nil
  def __key_to_claim_name__(key), do: key_to_claim_name(key)
end
