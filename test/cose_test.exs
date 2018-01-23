defmodule COSETest do
  use ExUnit.Case
  doctest COSE

  test "greets the world" do
    assert COSE.hello() == :world
  end
end
