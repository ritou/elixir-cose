defmodule CoseTest do
  use ExUnit.Case
  doctest Cose

  test "greets the world" do
    assert Cose.hello() == :world
  end
end
