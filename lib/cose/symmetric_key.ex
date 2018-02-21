defmodule COSE.SymmetricKey do
  @moduledoc """
  Symmetric Key Struct for HMAC and AES-CBC-MAC
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
    :HMAC_256_64 => 4,
    :HMAC_256 => 5,
    :HMAC_384 => 6,
    :HMAC_512 => 7,
    :AES_MAC_128_64 => 14,
    :AES_MAC_256_64 => 15,
    :AES_MAC_128_128 => 25,
    :AES_MAC_256_128 => 26,
  }
  @header_alg_value_map @header_alg_map |> Enum.into(%{}, fn {k, v} -> {v, k} end)

  @alg_key_length_map %{
    :AES_MAC_128_64 => 16,
    :AES_MAC_256_64 => 32,
    :AES_MAC_128_128 => 16,
    :AES_MAC_256_128 => 32,
  }

  @type t :: %__MODULE__{k: binary, kid: binary, alg: String.t()}

  @doc """
  ```
  sym_key = COSE.SymmetricKey.new([k: key, kid: kid, alg: alg])
  ```
  """
  @spec new(opts :: Keywords.t()) :: t | {:error, :invalid_key_length}
  def new(opts) do
    if valid_key_length?(opts) do
      struct(__MODULE__, Map.new(opts))
    else
      {:error, :invalid_key_length}
    end
  end

  defp valid_key_length?(opts) do
    case @alg_key_length_map[opts[:alg]] do
      nil -> true
      len -> len == byte_size(opts[:k])
    end
  end 

  @spec to_cwt_header(t) :: tuple
  def to_cwt_header(sim_key) do
    protected = to_protected(sim_key)
    unprotected = to_unprotected(sim_key)
    {protected, unprotected}
  end

  defp to_protected(sim_key) do
    %{@header_keys[:alg] => @header_alg_map[sim_key.alg]} |> CBOR.encode()
  end

  defp to_unprotected(%__MODULE__{kid: kid}) when not is_nil(kid), do: %{@header_keys[:kid] => kid}
  defp to_unprotected(_), do: %{}

  @spec tag(structure :: any, sim_key :: t) :: binary | nil
  def tag(structure, sim_key) do
    case sim_key.alg do
      :HMAC_256_64 -> tag_hmac_256_64(structure, sim_key.k)
      :HMAC_256 -> tag_hmac_256(structure, sim_key.k)
      :HMAC_384 -> tag_hmac_384(structure, sim_key.k)
      :HMAC_512 -> tag_hmac_512(structure, sim_key.k)
      :AES_MAC_128_64 -> tag_aes_mac_64(structure, sim_key.k)
      :AES_MAC_256_64 -> tag_aes_mac_64(structure, sim_key.k)
      :AES_MAC_128_128 -> tag_aes_mac_128(structure, sim_key.k)
      :AES_MAC_256_128 -> tag_aes_mac_128(structure, sim_key.k)
      _ -> nil
    end
  end

  defp tag_hmac_256_64(content, k), do: :crypto.hmac(:sha256, k, content, 8)

  defp tag_hmac_256(content, k), do: :crypto.hmac(:sha256, k, content)

  defp tag_hmac_384(content, k), do: :crypto.hmac(:sha384, k, content)

  defp tag_hmac_512(content, k), do: :crypto.hmac(:sha512, k, content)

  defp tag_aes_mac_64(content, k), do: :crypto.cmac(:aes_cbc, k, content, 8)

  defp tag_aes_mac_128(content, k), do: :crypto.cmac(:aes_cbc, k, content, 16)

  @spec validate_protected(protected :: binary, key :: t) ::
    :ok |
    {:error, :invalid_protected} |
    {:error, :invalid_alg}
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
      _ -> {:error, :invalid_protected}
    end
  end

  @spec validate_unprotected(unprotected :: map, key :: t) ::
    :ok |
    {:error, :invalid_unprotected} |
    {:error, :invalid_kid}
  def validate_unprotected(unprotected, key) when is_map(unprotected) do
    cond do
      is_nil(unprotected[@header_keys[:kid]]) ->
        if key.kid do
          {:error, :invalid_unprotected}
        else
          :ok
        end
      unprotected[@header_keys[:kid]] == key.kid -> :ok
      true -> {:error, :invalid_kid}
    end
  end
  def validate_unprotected(_, _), do: {:error, :invalid_unprotected}
end
