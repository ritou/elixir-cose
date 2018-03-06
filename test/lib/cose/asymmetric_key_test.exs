defmodule COSE.AsymmetricKeyTest do
  use ExUnit.Case

  alias COSE.AsymmetricKey
  doctest AsymmetricKey

  test "ES256" do
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = JOSE.JWK.generate_key(:secp256r1)
    kid = "Asymmetric256"
    alg = :ES256

    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert asym_key.k == k
    assert asym_key.kid == kid
    assert asym_key.alg == alg

    assert {<<161, 1, 38>>, %{4 => "Asymmetric256"}} == AsymmetricKey.to_cwt_header(asym_key)

    payload = "sample payload"
    sig = AsymmetricKey.sign(payload, asym_key)
    assert sig |> byte_size() == 64
  end

  test "ES384" do
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = JOSE.JWK.generate_key(:secp384r1)
    kid = "Asymmetric384"
    alg = :ES384

    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert asym_key.k == k
    assert asym_key.kid == kid
    assert asym_key.alg == alg

    assert {<<161, 1, 56, 34>>, %{4 => "Asymmetric384"}} == AsymmetricKey.to_cwt_header(asym_key)

    payload = "sample payload"
    sig = AsymmetricKey.sign(payload, asym_key)
    assert sig |> byte_size() == 96
  end

  test "ES512" do
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = JOSE.JWK.generate_key(:secp521r1)
    kid = "Asymmetric512"
    alg = :ES512

    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert asym_key.k == k
    assert asym_key.kid == kid
    assert asym_key.alg == alg

    assert {<<161, 1, 56, 35>>, %{4 => "Asymmetric512"}} == AsymmetricKey.to_cwt_header(asym_key)

    payload = "sample payload"
    sig = AsymmetricKey.sign(payload, asym_key)
    assert sig |> byte_size() == 128
  end
end
