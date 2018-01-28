defmodule COSE.CWT.Mac0Test do
  use ExUnit.Case

  alias COSE.CWT.Mac0
  doctest Mac0

  alias COSE.SymmetricKey

  test "HMAC_256_64" do
    k =
      Base.decode16!(
        "403697de87af64611c1d32a05dab0fe1fcb715a86ab435f1ec99192d79569388",
        case: :lower
      )

    kid = "Symmetric256"
    alg = :HMAC_256_64

    key = SymmetricKey.new(k: k, kid: kid, alg: alg)

    payload = %{"foo" => "bar"}
    mac0_object = Mac0.to_object(payload, key)

    assert mac0_object == [
             <<161, 1, 4>>,
             %{4 => "Symmetric256"},
             <<191, 99, 102, 111, 111, 99, 98, 97, 114, 255>>,
             <<69, 160, 229, 195, 127, 146, 77, 28>>
           ]

    mac0_tagged_object = Mac0.to_tagged_object(payload, key)

    assert mac0_tagged_object ==
             {:tag, 17,
              [
                <<161, 1, 4>>,
                %{4 => "Symmetric256"},
                <<191, 99, 102, 111, 111, 99, 98, 97, 114, 255>>,
                <<69, 160, 229, 195, 127, 146, 77, 28>>
              ]}

    assert Mac0.valid_tag?(mac0_object, key)
  end
end
