defmodule COSE.SymmetricKey do
  @moduledoc """
  Symmetric Key Struct for HMAC Key
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
    :HMAC_512 => 7
  }

  @type t :: %__MODULE__{k: binary, kid: binary, alg: String.t()}

  @doc """
  ```
  sym_key = COSE.SymmetricKey.new([k: key, kid: kid, alg: alg])
  ```
  """
  @spec new(opts :: Keywords.t()) :: t
  def new(opts) do
    struct(__MODULE__, Map.new(opts))
  end

  @spec to_cwt_header(t) :: tuple
  def to_cwt_header(sim_key) do
    protected = to_protected(sim_key)
    unprotected = %{@header_keys[:kid] => sim_key.kid}
    {protected, unprotected}
  end

  defp to_protected(sim_key) do
    %{@header_keys[:alg] => @header_alg_map[sim_key.alg]} |> CBOR.encode()
  end

  @spec tag(content :: any, sim_key :: t) :: binary | nil
  def tag(content, sim_key) do
    case sim_key.alg do
      :HMAC_256_64 -> tag_hmac_256_64(content, sim_key.k)
      :HMAC_256 -> tag_hmac_256(content, sim_key.k)
      :HMAC_384 -> tag_hmac_384(content, sim_key.k)
      :HMAC_512 -> tag_hmac_512(content, sim_key.k)
      _ -> nil
    end
  end

  defp tag_hmac_256_64(content, k), do: :crypto.hmac(:sha256, k, content) |> truncate_to_64_bits()

  defp truncate_to_64_bits(tag), do: tag |> binary_part(0, 8)

  defp tag_hmac_256(content, k), do: :crypto.hmac(:sha256, k, content)

  defp tag_hmac_384(content, k), do: :crypto.hmac(:sha384, k, content)

  defp tag_hmac_512(content, k), do: :crypto.hmac(:sha512, k, content)
end
