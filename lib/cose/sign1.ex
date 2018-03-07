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

    [protected, unprotected, payload, signature]
  end

  # TODO: Error Handling
  def to_object(_, _), do: nil

  defp build_signature(key, payload) do
    {protected, _} = AsymmetricKey.to_cwt_header(key)
    sign1_structure = [{:text, @sign1_structure_id}, protected, "", payload]
    AsymmetricKey.sign(sign1_structure |> CBOR.encode(), key)
  end

  @spec validate(object :: list, key :: AsymmetricKey.t()) ::
          :ok
          | {:error, :invalid_protected}
          | {:error, :invalid_alg}
          | {:error, :invalid_unprotected}
          | {:error, :invalid_kid}
          | {:error, :invalid_signature}
  def validate([protected, unprotected, payload, signature], key = %AsymmetricKey{}) do
    with :ok <- AsymmetricKey.validate_protected(protected, key),
         :ok <- AsymmetricKey.validate_unprotected(unprotected, key),
         :ok <- validate_signature(key, payload, signature) do
      :ok
    else
      e -> e
    end
  end

  defp validate_signature(key, payload, signature) do
    {protected, _} = AsymmetricKey.to_cwt_header(key)
    sign1_structure = [{:text, @sign1_structure_id}, protected, "", payload]
    AsymmetricKey.verify(sign1_structure |> CBOR.encode(), key, signature)
  end
end
