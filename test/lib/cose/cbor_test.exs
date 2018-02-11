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
    # NOTE: https://tools.ietf.org/html/rfc7049#appendix-A
    assert CBOR.encode(0, [to_hex: true]) == "00"
    assert CBOR.encode(1, [to_hex: true]) == "01"
    assert CBOR.encode(10, [to_hex: true]) == "0a"
    assert CBOR.encode(23, [to_hex: true]) == "17"
    assert CBOR.encode(24, [to_hex: true]) == "1818"
    assert CBOR.encode(25, [to_hex: true]) == "1819"
    assert CBOR.encode(100, [to_hex: true]) == "1864"
    assert CBOR.encode(1000, [to_hex: true]) == "1903e8"
    assert CBOR.encode(1000000, [to_hex: true]) == "1a000f4240"
    assert CBOR.encode(1000000000000, [to_hex: true]) == "1b000000e8d4a51000"
    assert CBOR.encode(18446744073709551615, [to_hex: true]) == "1bffffffffffffffff"
    assert CBOR.encode(18446744073709551616, [to_hex: true]) == "c249010000000000000000"

    assert CBOR.encode(-18446744073709551616, [to_hex: true]) == "3bffffffffffffffff"
    assert CBOR.encode(-18446744073709551617, [to_hex: true]) == "c349010000000000000000"
    assert CBOR.encode(-1, [to_hex: true]) == "20"
    assert CBOR.encode(-10, [to_hex: true]) == "29"
    assert CBOR.encode(-100, [to_hex: true]) == "3863"
    assert CBOR.encode(-1000, [to_hex: true]) == "3903e7"

    #assert CBOR.encode(0.0, [to_hex: true]) == "f90000"
    #assert CBOR.encode(-0.0, [to_hex: true]) == "f98000"
    #assert CBOR.encode(1.0, [to_hex: true]) == "f93c00"
    #assert CBOR.encode(1.1, [to_hex: true]) == "fb3ff199999999999a"
    #assert CBOR.encode(1.5, [to_hex: true]) == "f93e00"
    #assert CBOR.encode(65504.0, [to_hex: true]) == "f97bff"
    #assert CBOR.encode(100000.0, [to_hex: true]) == "fa47c35000"
    #assert CBOR.encode(3.4028234663852886e+38, [to_hex: true]) == "fa7f7fffff"
    #assert CBOR.encode(1.0e+300, [to_hex: true]) == "fb7e37e43c8800759c"
    #assert CBOR.encode(5.960464477539063e-8, [to_hex: true]) == "f90001"
    #assert CBOR.encode(0.00006103515625, [to_hex: true]) == "f90400"
    #assert CBOR.encode(-4.0, [to_hex: true]) == "f9c400"
    #assert CBOR.encode(-4.1, [to_hex: true]) == "fbc010666666666666"

    assert CBOR.encode(false, [to_hex: true]) == "f4"
    assert CBOR.encode(true, [to_hex: true]) == "f5"
    assert CBOR.encode(:null, [to_hex: true]) == "f6"
    assert CBOR.encode(:undefined, [to_hex: true]) == "f7"

    assert CBOR.encode({:simple, 16}, [to_hex: true]) == "f0"
    assert CBOR.encode({:simple, 24}, [to_hex: true]) == "f818"
    assert CBOR.encode({:simple, 255}, [to_hex: true]) == "f8ff"

    assert CBOR.encode({:timetext, {:text, "2013-03-21T20:04:00Z"}}, [to_hex: true]) == "c074323031332d30332d32315432303a30343a30305a"
    assert CBOR.encode({:timeepoch, 1363896240}, [to_hex: true]) == "c11a514b67b0"
    assert CBOR.encode({:timeepoch, 1363896240.5}, [to_hex: true]) == "c1fb41d452d9ec200000"
    assert CBOR.encode({:tag, 23, <<1, 2, 3, 4>>}, [to_hex: true]) == "d74401020304"
    assert CBOR.encode({:tag, 24, "6449455446" |> Base.decode16!()}, [to_hex: true]) == "d818456449455446"
    assert CBOR.encode({:tag, 32, {:text, "http://www.example.com"}}, [to_hex: true]) == "d82076687474703a2f2f7777772e6578616d706c652e636f6d"
    assert CBOR.encode("" |> Base.decode16!(), [to_hex: true]) == "40"
    assert CBOR.encode("01020304" |> Base.decode16!(), [to_hex: true]) == "4401020304"
    assert CBOR.encode({:text, ""}, [to_hex: true]) == "60"
    assert CBOR.encode({:text, "a"}, [to_hex: true]) == "6161"
    assert CBOR.encode({:text, "IETF"}, [to_hex: true]) == "6449455446"
    assert CBOR.encode({:text, "\"\\"}, [to_hex: true]) == "62225c"
    assert CBOR.encode({:text, "\u00fc"}, [to_hex: true]) == "62c3bc"
    assert CBOR.encode({:text, "\u6c34"}, [to_hex: true]) == "63e6b0b4"
    #assert CBOR.encode({:text, "\ud800\udd51"}, [to_hex: true]) == "64f0908591"
    assert CBOR.encode([], [to_hex: true]) == "80"
    assert CBOR.encode([1, 2, 3], [to_hex: true]) == "83010203"
    assert CBOR.encode([1, [2, 3], [4, 5]], [to_hex: true]) == "8301820203820405"
    assert CBOR.encode([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], [to_hex: true]) == "98190102030405060708090a0b0c0d0e0f101112131415161718181819"
    assert CBOR.encode(%{}, [to_hex: true]) == "a0"
    assert CBOR.encode(%{1 => 2, 3 => 4}, [to_hex: true]) == "a201020304"
    assert CBOR.encode(%{{:text, "a"} => 1, {:text, "b"} => [2, 3]}, [to_hex: true]) == "a26161016162820203"
    assert CBOR.encode([{:text, "a"}, %{{:text, "b"} => {:text, "c"}}], [to_hex: true]) == "826161a161626163"
    assert CBOR.encode(%{{:text, "a"} => {:text, "A"}, {:text, "b"} => {:text, "B"}, {:text, "c"} => {:text, "C"}, {:text, "d"} => {:text, "D"}, {:text, "e"} => {:text, "E"}}, [to_hex: true]) == "a56161614161626142616361436164614461656145"

    # TODO: Indefinite
  end
end
