defmodule COSE.AsymmetricKeyTest do
  use ExUnit.Case

  alias COSE.AsymmetricKey
  doctest AsymmetricKey

  test "ES256" do
    priv_jwk = JOSE.JWK.generate_key(:secp256r1)
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk
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

    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)

    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk |> JOSE.JWK.to_public()
    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)
  end

  test "ES384" do
    priv_jwk = JOSE.JWK.generate_key(:secp384r1)
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk
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

    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)

    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk |> JOSE.JWK.to_public()
    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)
  end

  test "ES512" do
    priv_jwk = JOSE.JWK.generate_key(:secp521r1)
    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk
    kid = "Asymmetric512"
    alg = :ES512

    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert asym_key.k == k
    assert asym_key.kid == kid
    assert asym_key.alg == alg

    assert {<<161, 1, 56, 35>>, %{4 => "Asymmetric512"}} == AsymmetricKey.to_cwt_header(asym_key)

    payload = "sample payload"
    sig = AsymmetricKey.sign(payload, asym_key)
    assert sig |> byte_size() == 132

    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)

    %JOSE.JWK{kty: {:jose_jwk_kty_ec, k}} = priv_jwk |> JOSE.JWK.to_public()
    asym_key = AsymmetricKey.new(k: k, kid: kid, alg: alg)
    assert :ok == AsymmetricKey.verify(payload, asym_key, sig)
    assert {:error, :invalid_signature} == AsymmetricKey.verify(payload, asym_key, <<1, 2, 3, 4, 5>>)
  end
end
