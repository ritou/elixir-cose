defmodule COSE.CBORTest do
  use ExUnit.Case

  alias COSE.CBOR
  doctest CBOR

  test "tag" do
    object = ["testobj"]
    assert CBOR.tag(object, :COSE_Sign1) == {:tag, 18, object}
    assert CBOR.tag(object, :COSE_Sign1) |> CBOR.parse_tag() == {:COSE_Sign1, object}

    assert CBOR.tag(object, :COSE_Mac0) == {:tag, 17, object}
    assert CBOR.tag(object, :COSE_Mac0) |> CBOR.parse_tag() == {:COSE_Mac0, object}

    assert object |> CBOR.tag(:COSE_Mac0) == {:tag, 17, object}
    assert object |> CBOR.tag(:COSE_Mac0) |> CBOR.tag(:CWT_CBOR) == {:tag, 61, {:tag, 17, object}}

    assert object
           |> CBOR.tag(:COSE_Mac0)
           |> CBOR.tag(:CWT_CBOR)
           |> CBOR.parse_tag() == {:CWT_CBOR, {:tag, 17, object}}
  end

  test "encode" do
    for value <- [
          0,
          1,
          10,
          23,
          24,
          25,
          100,
          1000,
          1_000_000,
          1_000_000_000_000,
          18_446_744_073_709_551_615,
          -18_446_744_073_709_551_615,
          -1,
          -10,
          -100,
          -1000
        ] do
      assert CBOR.encode(value) == :cbor.encode(value)
    end

    for value <- [18_446_744_073_709_551_616, -18_446_744_073_709_551_616] do
      assert CBOR.encode(value) == :cbor.encode(value) |> :erlang.list_to_bitstring()
    end
  end
end
