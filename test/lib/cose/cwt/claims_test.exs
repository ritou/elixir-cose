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
    assert Claims.__key_to_claim_name__(2) == "sub"
    assert Claims.__key_to_claim_name__(3) == "aud"
    assert Claims.__key_to_claim_name__(4) == "exp"
    assert Claims.__key_to_claim_name__(5) == "nbf"
    assert Claims.__key_to_claim_name__(6) == "iat"
    assert Claims.__key_to_claim_name__(7) == "cti"
  end

  test "to_binary, to_map" do
    claims = %{
      "iss" => {:text, "coap://as.example.com"},
      "sub" => {:text, "erikw"},
      "aud" => {:text, "coap://light.example.com"},
      "iat" => 1_443_944_944,
      "exp" => 1_444_064_944,
      "nbf" => 1_443_944_944,
      "cti" => "0b71" |> Base.decode16!(case: :lower)
    }

    hex = Claims.to_binary(claims) |> Base.encode16(case: :lower)
    cbor_claims = hex |> Base.decode16!(case: :lower) |> CBOR.decode()
    assert cbor_claims[1] == "coap://as.example.com"
    assert cbor_claims[2] == "erikw"
    assert cbor_claims[3] == "coap://light.example.com"
    assert cbor_claims[4] == 1_444_064_944
    assert cbor_claims[5] == 1_443_944_944
    assert cbor_claims[6] == 1_443_944_944
    assert cbor_claims[7] == "\vq"

    assert is_nil(Claims.to_map(""))
    assert is_nil(Claims.to_map("invalid"))
  end
end
