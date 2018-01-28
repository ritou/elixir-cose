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
end
