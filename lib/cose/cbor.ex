defmodule COSE.CBOR do
  @moduledoc """
  Erlang CBOR Wrapper module
  """

  @spec encode(value :: any) :: binary
  def encode(value), do: :cbor.encode(value) |> :erlang.list_to_binary()
  @spec encode(cbor_binary :: binary) :: any
  def decode(binary), do: :cbor.decode(binary)

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
end
