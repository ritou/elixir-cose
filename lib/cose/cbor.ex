defmodule COSE.CBOR do
  @moduledoc """
  Erlang CBOR Wrapper module
  """

  @cbor_tag_key %{
    :CWT_CBOR => 61,
    :COSE_Sign1 => 18,
    :COSE_Mac0 => 17
  }
  @cbor_tag_value @cbor_tag_key |> Enum.into(%{}, fn {k, v} -> {v, k} end)

  @spec tag(cwt :: any, tag :: atom) :: tuple | nil
  def tag(object, tag) when is_atom(tag) do
    case @cbor_tag_key[tag] do
      nil -> nil
      tag_value -> {:tag, tag_value, object}
    end
  end

  def tag(_, _), do: nil

  @spec parse_tag(tagged_cwt :: tuple) :: {tag_key :: atom, object :: any} | nil
  def parse_tag({:tag, tag_value, object}) when is_integer(tag_value) do
    case @cbor_tag_value[tag_value] do
      nil -> nil
      tag_key -> {tag_key, object}
    end
  end

  def parse_tag(_), do: nil

  # TODO: bignum
  def encode(num) when is_integer(num) and num > 18_446_744_073_709_551_615,
    do: :cbor.encode(num) |> :erlang.list_to_binary()

  # number
  def encode(num) when is_integer(num) and num > 4_294_967_295, do: <<27>> <> <<num::size(64)>>
  def encode(num) when is_integer(num) and num > 65535, do: <<26>> <> <<num::size(32)>>
  def encode(num) when is_integer(num) and num > 255, do: <<25>> <> <<num::size(16)>>
  def encode(num) when is_integer(num) and num > 23, do: <<24, num>>
  def encode(num) when is_integer(num) and num >= 0, do: <<num>>

  # negative number
  def encode(num) when is_integer(num) and num >= -24, do: <<num * -1 + 31>>
  def encode(num) when is_integer(num) and num >= -255, do: <<56, (num + 1) * -1>>
  def encode(num) when is_integer(num) and num >= -65535, do: <<57, (num + 1) * -1::size(16)>>

  def encode(num) when is_integer(num) and num >= -4_294_967_295,
    do: <<58, (num + 1) * -1::size(32)>>

  def encode(num) when is_integer(num) and num >= -18_446_744_073_709_551_615,
    do: <<59, (num + 1) * -1::size(64)>>

  # TODO: negative bignum
  def encode(num) when is_integer(num) and num < -18_446_744_073_709_551_615,
    do: :cbor.encode(num) |> :erlang.list_to_binary()

  def encode(value), do: :cbor.encode(value) |> :erlang.list_to_binary()

  @spec encode(cbor_binary :: binary) :: any
  def decode(binary), do: :cbor.decode(binary)
end
