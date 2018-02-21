defmodule COSE.SymmetricKeyTest do
  use ExUnit.Case

  alias COSE.SymmetricKey
  doctest SymmetricKey

  test "HMAC_256_64" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_256_64

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 4>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 8
  end

  test "HMAC_256" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_256

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 5>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 32
  end

  test "HMAC_384" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_384

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 6>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 48
  end

  test "HMAC_512" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_512

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 7>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 64
  end

  test "AES_CBC_128_64" do
    k =
      Base.decode16!(
        "231f4c4d4d3051fdc2ec0a3851d5b383",
        case: :lower
      )

    kid = "Symmetric128"
    alg = :AES_MAC_128_64

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 14>>, %{4 => "Symmetric128"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 8
  end

  test "AES_CBC_256_64" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :AES_MAC_256_64

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 15>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 8
  end

  test "AES_CBC_128_128" do
    k =
      Base.decode16!(
        "231f4c4d4d3051fdc2ec0a3851d5b383",
        case: :lower
      )

    kid = "Symmetric128"
    alg = :AES_MAC_128_128

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 24, 25>>, %{4 => "Symmetric128"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 16
  end

  test "AES_CBC_256_128" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :AES_MAC_256_128

    sym_key = SymmetricKey.new(k: k, kid: kid, alg: alg)
    assert sym_key.k == k
    assert sym_key.kid == kid
    assert sym_key.alg == alg

    assert {<<161, 1, 24, 26>>, %{4 => "Symmetric256"}} == SymmetricKey.to_cwt_header(sym_key)

    payload = "sample payload"
    tag = SymmetricKey.tag(payload, sym_key)
    assert tag |> byte_size() == 16
  end
end
