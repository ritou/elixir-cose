defmodule COSE.CBOR do
  @moduledoc """
  Functions for handling CBOR Object

  * Tag
  * Encode/Decode functions
  """

  require Logger

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

  # Encoder
  def encode(value, to_hex: true) do
    encode(value) |> Base.encode16(case: :lower)
  end

  # unsigned int
  def encode(num) when is_integer(num) and num > 18_446_744_073_709_551_615 do
    [<<194>>, encode_bin(size256(num), bignum_bytes(num))]
    |> :erlang.list_to_bitstring()
  end

  def encode(num) when is_integer(num) and num > 4_294_967_295, do: <<27>> <> <<num::size(64)>>

  def encode(num) when is_integer(num) and num > 65535, do: <<26>> <> <<num::size(32)>>
  def encode(num) when is_integer(num) and num > 255, do: <<25>> <> <<num::size(16)>>
  def encode(num) when is_integer(num) and num > 23, do: <<24, num>>
  def encode(num) when is_integer(num) and num >= 0 and num <= 23, do: <<num>>

  # negative int
  def encode(num) when is_integer(num) and num >= -24, do: <<num * -1 + 31>>
  def encode(num) when is_integer(num) and num >= -255, do: <<56, (num + 1) * -1>>
  def encode(num) when is_integer(num) and num >= -65535, do: <<57, (num + 1) * -1::size(16)>>

  def encode(num) when is_integer(num) and num >= -4_294_967_295,
    do: <<58, (num + 1) * -1::size(32)>>

  def encode(num) when is_integer(num) and num >= -18_446_744_073_709_551_616,
    do: <<59, (num + 1) * -1::size(64)>>

  # negative bignum
  def encode(num) when is_integer(num) and num < -18_446_744_073_709_551_616 do
    inv = -1 - num

    [<<195>>, encode_bin(size256(inv), bignum_bytes(inv))]
    |> :erlang.list_to_bitstring()
  end

  # map
  def encode(map) when is_map(map) do
    len = map_size(map)

    map_initial_byte(len) <>
      (map
       |> Map.to_list()
       |> Enum.flat_map(fn {k, v} -> [k, v] end)
       |> Enum.map_join(&encode(&1)))
  end

  # list
  def encode(list) when is_list(list) do
    list_initial_byte(length(list)) <> (list |> Enum.map_join(&encode(&1)))
  end

  # bytes
  def encode(binary) when is_binary(binary) do
    binary |> encode_bin(byte_size(binary))
  end

  # text
  def encode({:text, text}) when is_binary(text) do
    text |> encode_text(byte_size(text))
  end

  def encode(false), do: <<244>>
  def encode(true), do: <<245>>
  def encode(nil), do: <<246>>
  def encode(:null), do: <<246>>
  def encode(:undefined), do: <<247>>

  # simple
  def encode({:simple, value}) when is_integer(value) and value >= 0 and value <= 19 do
    <<224 + value>>
  end

  def encode({:simple, value}) when is_integer(value) and value > 19 and value <= 255 do
    <<248, value>>
  end

  ## not supported
  def encode({:simple, _}), do: <<0>>

  # tag
  def encode({:timetext, timetext}), do: encode_tag(0, timetext)
  def encode({:timeepoch, timeepoch}), do: encode_tag(1, timeepoch)
  def encode({:tag, tag, value}), do: encode_tag(tag, value)

  # TODO: Floating-Point Numbers
  def encode(float) when is_float(float), do: encode_with_erlang(float)

  # TODO: Indefinite Lengths for Some Major Types

  # other
  def encode(value) do
    encode_with_erlang(value)
  end

  defp encode_with_erlang(value) do
    Logger.debug("NOTE: encode #{inspect(value)} with :cbor.encode/1")
    encoded = :cbor.encode(value)

    if is_binary(encoded) do
      encoded
    else
      encoded |> :erlang.list_to_binary()
    end
  end

  defp map_initial_byte(len) when len <= 23, do: <<160 + len>>
  defp map_initial_byte(len) when len <= 255, do: <<184, len>>
  defp map_initial_byte(len) when len <= 65535, do: <<185, len::size(16)>>
  defp map_initial_byte(len) when len <= 4_294_967_295, do: <<186, len::size(32)>>
  defp map_initial_byte(len) when len <= 18_446_744_073_709_551_615, do: <<187, len::size(64)>>
  # not supported
  defp map_initial_byte(_), do: <<0>>

  defp encode_text(_, len) when len == 0, do: <<96>>
  defp encode_text(value, len) when len <= 23, do: <<96 + len>> <> value
  defp encode_text(value, len) when len <= 255, do: <<120, len>> <> value
  defp encode_text(value, len) when len <= 65535, do: <<121, len::size(16)>> <> value
  defp encode_text(value, len) when len <= 4_294_967_295, do: <<122, len::size(32)>> <> value

  defp encode_text(value, len) when len <= 18_446_744_073_709_551_615,
    do: <<123, len::size(64)>> <> value

  # not supported
  defp encode_text(_, _), do: <<0>>

  defp encode_bin(_, len) when len == 0, do: <<64>>
  defp encode_bin(value, len) when len <= 23, do: <<64 + len>> <> value
  defp encode_bin(value, len) when len <= 255, do: <<88, len>> <> value
  defp encode_bin(value, len) when len <= 65535, do: <<89, len::size(16)>> <> value
  defp encode_bin(value, len) when len <= 4_294_967_295, do: <<90, len::size(32)>> <> value

  defp encode_bin(value, len) when len <= 18_446_744_073_709_551_615,
    do: <<91, len::size(64)>> <> value

  # not supported
  defp encode_bin(_, _), do: <<0>>

  defp list_initial_byte(len) when len <= 23, do: <<128 + len>>
  defp list_initial_byte(len) when len <= 255, do: <<152, len>>
  defp list_initial_byte(len) when len <= 65535, do: <<153, len::size(16)>>
  defp list_initial_byte(len) when len <= 4_294_967_295, do: <<154, len::size(32)>>
  defp list_initial_byte(len) when len <= 18_446_744_073_709_551_615, do: <<155, len::size(64)>>
  # not supported
  defp list_initial_byte(_), do: <<0>>

  defp size256(num), do: <<num::size(256)>> |> binary_part(32, -1 * bignum_bytes(num))
  defp bignum_bytes(num) when num > 255, do: 1 + bignum_bytes(div(num, 256))
  defp bignum_bytes(_), do: 1

  defp encode_tag(tag, value) when tag >= 0 and tag <= 23, do: <<192 + tag>> <> encode(value)
  defp encode_tag(tag, value) when tag <= 255, do: <<216, tag>> <> encode(value)
  defp encode_tag(tag, value) when tag <= 65535, do: <<217, tag::size(16)>> <> encode(value)

  defp encode_tag(tag, value) when tag <= 4_294_967_295,
    do: <<218, tag::size(32)>> <> encode(value)

  defp encode_tag(tag, value) when tag <= 18_446_744_073_709_551_615,
    do: <<91, tag::size(64)>> <> encode(value)

  # not supported
  defp encode_tag(_, _), do: <<0>>

  @spec decode(cbor_binary :: binary) :: any
  def decode(binary), do: :cbor.decode(binary)
end
