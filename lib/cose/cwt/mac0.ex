defmodule COSE.CWT.Mac0 do
  @moduledoc """
  functions for handling COSE_Mac0 object
  """

  alias COSE.{CBOR, SymmetricKey}

  @spec to_object(raw_payload :: any, key :: SymmetricKey) :: list
  def to_object(raw_payload, key = %SymmetricKey{}) do
    {protected, unprotected} = SymmetricKey.to_cwt_header(key)
    payload = raw_payload |> CBOR.encode()
    tag = SymmetricKey.tag(payload, key)

    [
      protected,
      unprotected,
      payload,
      tag
    ]
  end

  def to_object(_, _), do: nil

  def to_tagged_object(raw_payload, key = %SymmetricKey{}) do
    to_object(raw_payload, key) |> CBOR.tag(:COSE_Mac0)
  end

  def to_tagged_object(_, _), do: nil
end
