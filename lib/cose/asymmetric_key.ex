defmodule COSE.AsymmetricKey do
  @moduledoc """
  Asymmetric Key Struct for ECDSA
  """

  alias COSE.CBOR

  defstruct [
    :k,
    :kid,
    :alg
  ]

  @header_keys %{
    :alg => 1,
    :kid => 4
  }

  @header_alg_map %{
    :ES256 => -7,
    :ES384 => -35,
    :ES512 => -36
  }
  @header_alg_value_map @header_alg_map |> Enum.into(%{}, fn {k, v} -> {v, k} end)

  @type t :: %__MODULE__{k: binary, kid: binary, alg: atom}

  @doc """
  ```
  key = %{key_map = %{"crv" => "P-256", "kty" => "EC2", "x" => ...}
        |> COSE.AsymmetricKey.ECDSA.from_map()
  asym_key = COSE.AsymmetricKey.new([k: key, kid: kid, alg: alg])
  ```
  """
  @spec new(opts :: Keywords.t()) :: t
  def new(opts) do
    struct(__MODULE__, Map.new(opts))
  end

  @spec to_cwt_header(t) :: tuple
  def to_cwt_header(asym_key) do
    protected = to_protected(asym_key)
    unprotected = to_unprotected(asym_key)
    {protected, unprotected}
  end

  defp to_protected(asym_key) do
    %{@header_keys[:alg] => @header_alg_map[asym_key.alg]} |> CBOR.encode()
  end

  defp to_unprotected(%__MODULE__{kid: kid}) when not is_nil(kid),
    do: %{@header_keys[:kid] => kid}

  defp to_unprotected(_), do: %{}

  @doc """
  ```
  asym_key = COSE.AsymmetricKey.new([k: key, kid: kid, alg: alg])
  sig = COSE.AsymmetricKey.sign(data, asym_key)
  ```
  """
  @spec sign(structure :: any, asym_key :: t) :: binary | nil
  def sign(structure, asym_key) do
    case asym_key.alg do
      :ES256 -> sign_with_es256(structure, asym_key.k)
      :ES384 -> sign_with_es384(structure, asym_key.k)
      :ES512 -> sign_with_es512(structure, asym_key.k)
      _ -> nil
    end
  end

  # NOTE: If there is a length mismatch of r, s, sign it again
  defp sign_with_es256(content, k) do
    der_sig = :public_key.sign(content, :sha256, k)

    case der_sig |> der_to_bin(256) do
      nil -> sign_with_es256(content, k)
      sig -> sig
    end
  end

  defp sign_with_es384(content, k) do
    der_sig = :public_key.sign(content, :sha384, k)

    case der_sig |> der_to_bin(384) do
      nil -> sign_with_es384(content, k)
      sig -> sig
    end
  end

  defp sign_with_es512(content, k) do
    der_sig = :public_key.sign(content, :sha512, k)

    case der_sig |> der_to_bin(521) do
      nil -> sign_with_es512(content, k)
      sig -> sig
    end
  end

  defp der_to_bin(der_sig = <<48, _::binary>>, key_size_bits) do
    key_size_bytes = div(key_size_bits + 7, 8)

    r_begin =
      case binary_part(der_sig, 1, 1) do
        <<len>> when len < 128 ->
          3

        # NOTE: not support valiable length
        _ ->
          4
      end

    <<r_len>> = der_sig |> binary_part(r_begin, 1)
    <<s_len>> = der_sig |> binary_part(r_begin + r_len + 2, 1)

    if r_len == key_size_bytes && s_len == key_size_bytes do
      (der_sig |> binary_part(r_begin + 1, key_size_bytes)) <>
        (der_sig |> binary_part(r_begin + key_size_bytes + 3, key_size_bytes))
    else
      nil
    end
  end

  defp der_to_bin(_, _), do: nil

  @spec verify(structure :: any, asym_key :: t, signature :: binary) ::
          :ok | {:error, :invalid_signature}
  def verify(structure, asym_key, signature) do
    case asym_key.alg do
      :ES256 -> signature |> verify_with_es256(structure, asym_key.k)
      :ES384 -> signature |> verify_with_es384(structure, asym_key.k)
      :ES512 -> signature |> verify_with_es512(structure, asym_key.k)
      _ -> nil
    end
    |> if do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp bin_to_der(sig, key_size_bits) do
    try do
      key_size_bytes = div(key_size_bits + 7, 8)
      r = sig |> binary_part(0, key_size_bytes)
      s = sig |> binary_part(key_size_bytes, key_size_bytes)
      encode_der_ecdsa_sig(r, s)
    rescue
      _ -> nil
    end
  end

  defp encode_der_ecdsa_sig(r, s) when is_binary(r) and is_binary(s) do
    der_len = byte_size(r) + byte_size(s) + 4

    der =
      if der_len < 128 do
        <<48>> <> <<der_len>>
      else
        <<48, 129>> <> <<der_len>>
      end

    der <> <<2, byte_size(r)>> <> r <> <<2, byte_size(s)>> <> s
  end

  defp verify_with_es256(bin_sig, content, k) do
    case bin_sig |> bin_to_der(256) do
      nil -> false
      der_sig -> :public_key.verify(content, :sha256, der_sig, k)
    end
  end

  defp verify_with_es384(bin_sig, content, k) do
    case bin_sig |> bin_to_der(384) do
      nil -> false
      der_sig -> :public_key.verify(content, :sha384, der_sig, k)
    end
  end

  defp verify_with_es512(bin_sig, content, k) do
    case bin_sig |> bin_to_der(521) do
      nil -> false
      der_sig -> :public_key.verify(content, :sha512, der_sig, k)
    end
  end

  @spec validate_protected(protected :: binary, key :: t) ::
          :ok
          | {:error, :invalid_protected}
          | {:error, :invalid_alg}
  def validate_protected(protected, key) do
    case protected |> CBOR.decode() do
      decoded when is_map(decoded) ->
        if decoded[@header_keys[:alg]] && @header_alg_value_map[decoded[@header_keys[:alg]]] do
          if @header_alg_value_map[decoded[@header_keys[:alg]]] == key.alg do
            :ok
          else
            {:error, :invalid_alg}
          end
        else
          {:error, :invalid_alg}
        end

      _ ->
        {:error, :invalid_protected}
    end
  end

  @spec validate_unprotected(unprotected :: map, key :: t) ::
          :ok
          | {:error, :invalid_unprotected}
          | {:error, :invalid_kid}
  def validate_unprotected(unprotected, key) when is_map(unprotected) do
    cond do
      is_nil(unprotected[@header_keys[:kid]]) ->
        if key.kid do
          {:error, :invalid_unprotected}
        else
          :ok
        end

      unprotected[@header_keys[:kid]] == key.kid ->
        :ok

      true ->
        {:error, :invalid_kid}
    end
  end

  def validate_unprotected(_, _), do: {:error, :invalid_unprotected}
end
