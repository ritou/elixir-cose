defmodule COSE.Sign1 do
  @moduledoc """
  functions for handling COSE_Mac0 object
  """

  alias COSE.{CBOR, AsymmetricKey}

  @sign1_structure_id "Signature1"

  @spec to_object(payload :: any, key :: AsymmetricKey) :: list
  def to_object(payload, key = %AsymmetricKey{}) do
    {protected, unprotected} = AsymmetricKey.to_cwt_header(key)
    signature = build_signature(key, payload)

    [protected,
     unprotected,
     payload,
     signature]
  end

  # TODO: Error Handling
  def to_object(_, _), do: nil

  defp build_signature(key, payload) do
    {protected, _} = AsymmetricKey.to_cwt_header(key)
    sign1_structure = [{:text, @sign1_structure_id}, protected, "", payload]
    AsymmetricKey.sign(sign1_structure |> CBOR.encode(), key)
  end
end
