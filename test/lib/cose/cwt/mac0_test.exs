defmodule COSE.CWT.Mac0Test do
  use ExUnit.Case

  alias COSE.CWT.Mac0
  doctest Mac0

  alias COSE.{SymmetricKey, CBOR}

  test "HMAC_256_64" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_256_64

    key = SymmetricKey.new(k: k, kid: kid, alg: alg)

    payload =
      %{1 => {:text, "coap://as.example.com"},
        2 => {:text, "erikw"},
        3 => {:text, "coap://light.example.com"},
        4 => 1444064944,
        5 => 1443944944,
        6 => 1443944944,
        7 => "0b71" |> Base.decode16!(case: :lower)}

    [protected, unprotected, decoded_payload, tag] = Mac0.to_object(payload, key)
    assert protected |> CBOR.decode() == %{1 => 4}
    assert unprotected == %{4 => "Symmetric256"}
    assert decoded_payload |> CBOR.decode() ==
      %{
        1 => "coap://as.example.com",
        2 => "erikw",
        3 => "coap://light.example.com",
        4 => 1444064944,
        5 => 1443944944,
        6 => 1443944944,
        7 => "\vq"
      }
    assert byte_size(tag) == 8

    assert Mac0.to_object(payload, key) |> Mac0.validate(key)
  end
end
