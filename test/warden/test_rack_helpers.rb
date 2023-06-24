# frozen_string_literal: true

require "test_helper"

class Warden::TestRackHelpers < Minitest::Test
  class TestClass
    include Warden::WebAuthn::RackHelpers
  end

  class CustomizedClass
    include Warden::WebAuthn::RackHelpers

    def relying_party_key
      "custom_relying_party"
    end
  end

  def test_default_keys
    assert_equal "warden.webauthn.relying_party", TestClass.new.relying_party_key
  end

  def test_custom_keys
    assert_equal "custom_relying_party", CustomizedClass.new.relying_party_key
  end
end
