defmodule COSE.Mac0 do
  @moduledoc """
  functions for handling COSE_Mac0 object
  """

  alias COSE.{CBOR, SymmetricKey}

  @mac0_structure_id "MAC0"

  @spec to_object(payload :: any, key :: SymmetricKey) :: list
  def to_object(payload, key = %SymmetricKey{}) do
    {protected, unprotected} = SymmetricKey.to_cwt_header(key)
    tag = build_tag(key, payload)

    [protected, unprotected, payload, tag]
  end

  # TODO: Error Handling
  def to_object(_, _), do: nil

  defp build_tag(key, payload) do
    {protected, _} = SymmetricKey.to_cwt_header(key)
    mac0_structure = [{:text, @mac0_structure_id}, protected, "", payload]
    SymmetricKey.tag(mac0_structure |> CBOR.encode(), key)
  end

  @spec validate(object :: list, key :: SymmetricKey.t()) ::
          :ok
          | {:error, :invalid_protected}
          | {:error, :invalid_alg}
          | {:error, :invalid_unprotected}
          | {:error, :invalid_kid}
          | {:error, :invalid_tag}
  def validate([protected, unprotected, payload, tag], key = %SymmetricKey{}) do
    with :ok <- SymmetricKey.validate_protected(protected, key),
         :ok <- SymmetricKey.validate_unprotected(unprotected, key),
         :ok <- validate_tag(key, payload, tag) do
      :ok
    else
      e -> e
    end
  end

  defp validate_tag(key, payload, tag) do
    expected_tag = build_tag(key, payload)

    if expected_tag == tag do
      :ok
    else
      {:error, :invalid_tag}
    end
  end
end
