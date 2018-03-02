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
    :ES512 => -36,
  }
  @header_alg_value_map @header_alg_map |> Enum.into(%{}, fn {k, v} -> {v, k} end)

  @type t :: %__MODULE__{k: binary, kid: binary, alg: String.t()}

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

  defp to_unprotected(%__MODULE__{kid: kid}) when not is_nil(kid), do: %{@header_keys[:kid] => kid}
  defp to_unprotected(_), do: %{}

  @spec sign(structure :: any, asym_key :: t) :: binary | nil
  def sign(structure, asym_key) do
    case asym_key.alg do
      :ES256 -> sign_with_es256(structure, asym_key.k)
      :ES384 -> sign_with_es384(structure, asym_key.k)
      :ES512 -> sign_with_es512(structure, asym_key.k)
      _ -> nil
    end
  end

  defp sign_with_es256(content, k), do: :public_key.sign(content, :sha256, k) 
  defp sign_with_es384(content, k), do: :public_key.sign(content, :sha384, k) 
  defp sign_with_es512(content, k), do: :public_key.sign(content, :sha512, k) 

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
