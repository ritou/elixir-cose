defmodule COSE.Sign1Test do
  use ExUnit.Case

  alias COSE.Sign1
  doctest Sign1

  alias COSE.{AsymmetricKey, CBOR}

  test "ES256" do
    priv_jwk = JOSE.JWK.generate_key(:secp256r1)
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk
    kid = "Asymmetric256"
    alg = :ES256

    key = AsymmetricKey.new(k: k, kid: kid, alg: alg)

    payload =
      %{
        1 => {:text, "coap://as.example.com"},
        2 => {:text, "erikw"},
        3 => {:text, "coap://light.example.com"},
        4 => 1_444_064_944,
        5 => 1_443_944_944,
        6 => 1_443_944_944,
        7 => "0b71" |> Base.decode16!(case: :lower)
      }
      |> CBOR.encode()

    [protected, unprotected, decoded_payload, signature] = Sign1.to_object(payload, key)
    assert protected |> CBOR.decode() == %{1 => -7}
    assert unprotected == %{4 => "Asymmetric256"}
    assert decoded_payload == payload
    assert byte_size(signature) == 64

    assert Sign1.to_object(payload, key) |> Sign1.validate(key) == :ok
  end
end
