defmodule COSE.CBOR do
  @moduledoc """
  Erlang CBOR Wrapper module
  """

  def encode(value) do
    :cbor.encode(value)
    |> :erlang.list_to_binary()
  end

  def decode(binary) do
    :cbor.decode(binary)
  end
end
