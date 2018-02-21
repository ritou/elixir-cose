defmodule COSE.Mac0Test do
  use ExUnit.Case

  alias COSE.Mac0
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
      |> CBOR.encode()

    [protected, unprotected, decoded_payload, tag] = Mac0.to_object(payload, key)
    assert protected |> CBOR.decode() == %{1 => 4}
    assert unprotected == %{4 => "Symmetric256"}
    assert decoded_payload == payload
    assert byte_size(tag) == 8

    # https://tools.ietf.org/html/draft-ietf-ace-cbor-web-token-12#appendix-A.4
    assert (Mac0.to_object(payload, key) |> CBOR.tag(:COSE_Mac0) |> CBOR.tag(:CWT_CBOR) |> CBOR.encode() |> Base.encode16(case: :lower))  == "d83dd18443a10104a1044c53796d6d65747269633235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7148093101ef6d789200"

    assert Mac0.to_object(payload, key) |> Mac0.validate_tag(key) == :ok
  end

  test "AES_MAC_128_128" do
    k =
      Base.decode16!(
        "231f4c4d4d3051fdc2ec0a3851d5b383",
        case: :lower
      )

    kid = "Symmetric128"
    alg = :AES_MAC_128_128

    key = SymmetricKey.new(k: k, kid: kid, alg: alg)

    payload =
      %{1 => {:text, "coap://as.example.com"},
        2 => {:text, "erikw"},
        3 => {:text, "coap://light.example.com"},
        4 => 1444064944,
        5 => 1443944944,
        6 => 1443944944,
        7 => "0b71" |> Base.decode16!(case: :lower)}
      |> CBOR.encode()

    [protected, unprotected, decoded_payload, tag] = Mac0.to_object(payload, key)
    assert protected |> CBOR.decode() == %{1 => 25}
    assert unprotected == %{4 => "Symmetric128"}
    assert decoded_payload == payload
    assert byte_size(tag) == 16

    assert Mac0.to_object(payload, key) |> Mac0.validate_tag(key) == :ok
  end
end
