defmodule COSE.CWT.ClaimsTest do
  use ExUnit.Case

  alias COSE.CBOR
  alias COSE.CWT.Claims
  doctest Claims

  test "__claim_name_to_key__, __key_to_claim_name__" do
    assert Claims.__claim_name_to_key__("iss") == 1
    assert Claims.__claim_name_to_key__("sub") == 2
    assert Claims.__claim_name_to_key__("aud") == 3
    assert Claims.__claim_name_to_key__("exp") == 4
    assert Claims.__claim_name_to_key__("nbf") == 5
    assert Claims.__claim_name_to_key__("iat") == 6
    assert Claims.__claim_name_to_key__("cti") == 7

    assert Claims.__key_to_claim_name__(1) == "iss"
  end

  test "to_binary, to_map" do
    claims = %{
      "aud" => "coap://light.example.com",
      "cti" => "\vq",
      "exp" => 1444064944,
      "iat" => 1443944944,
      "iss" => "coap://as.example.com",
      "nbf" => 1443944944,
      "sub" => "erikw"
    }
    hex = Claims.to_binary(claims) |> Base.encode16(case: :lower)

    assert hex == "bf0175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007620b71ff"

    cbor_claims = hex |> Base.decode16!(case: :lower) |> CBOR.decode()
    assert cbor_claims[1] == "coap://as.example.com"
    assert cbor_claims[2] == "erikw"
    assert cbor_claims[3] == "coap://light.example.com"
    assert cbor_claims[4] == 1_444_064_944
    assert cbor_claims[5] == 1_443_944_944
    assert cbor_claims[6] == 1_443_944_944
    assert cbor_claims[7] == "\vq"

    decoded_claims = hex |> Base.decode16!(case: :lower) |> Claims.to_map()
    assert claims == decoded_claims

    assert is_nil(Claims.to_map(""))
    assert is_nil(Claims.to_map("invalid"))
  end
end
