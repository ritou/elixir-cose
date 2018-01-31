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

  # binary(text or hexed binary)
  def encode(binary) when is_binary(binary) do
    case binary |> hexed?() do
      nil ->
        binary |> encode_text(byte_size(binary))

      decoded ->
        decoded |> encode_bin(byte_size(decoded))
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

  @spec decode(cbor_binary :: binary) :: any
  def decode(binary), do: :cbor.decode(binary)

  @hexed_regexp ~r/\Ah'([0-9a-fA-F]*)'\z/
  defp hexed?(value) do
    case Regex.run(@hexed_regexp, value) do
      [_, hexed] -> hexed |> String.downcase() |> Base.decode16!(case: :lower)
      _ -> nil
    end
  end
end
