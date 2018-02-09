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

  @spec validate(object :: any, key :: SymmetricKey) ::
    {:ok, payload :: any} |
    {:error, :invalid_protected} |
    {:error, :invalid_alg} |
    {:error, :invalid_unprotected} |
    {:error, :invalid_kid} |
    {:error, :invalid_tag}
  def validate(object = [protected, unprotected, payload, tag], key = %SymmetricKey{}) do
    with :ok <- validate_protected(protected, key),
         :ok <- validate_unprotected(unprotected, key),
         :ok <- validate_tag(tag, payload, key)
    do
      {:ok, payload}
    else
      {:error, _} = e -> e
    end
  end

  def validate_protected(protected, key) do
    {:error, :invalid_protected}
  end

  def validate_unprotected(unprotected, key) do
    {:error, :invalid_unprotected}
  end

  def validate_tag(tag, payload, key) do
    {:error, :invalid_tag}
  end
end
