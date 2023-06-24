# frozen_string_literal: true

require "test_helper"

class Warden::TestRackHelpers < Minitest::Test
  class TestClass
    include Warden::WebAuthn::RackHelpers

    attr_accessor :request

    def initialize
      self.request = Rack::Request.new({})
    end
  end

  class CustomizedClass
    include Warden::WebAuthn::RackHelpers

    attr_accessor :request

    def initialize
      self.request = Rack::Request.new({})
    end

    def relying_party_key
      "custom_relying_party"
    end

    def relying_party
      "dummy_relying_party_value"
    end
  end

  def test_default_keys
    assert_equal "warden.webauthn.relying_party", TestClass.new.relying_party_key
  end

  def test_custom_keys
    assert_equal "custom_relying_party", CustomizedClass.new.relying_party_key
  end

  def test_raises_name_error_if_no_relying_party_method
    assert_raises NameError do
      TestClass.new.set_relying_party_in_request_env
    end
  end

  def test_raises_uses_defined_relying_party_method
    instance = CustomizedClass.new
    instance.set_relying_party_in_request_env
    assert_equal "dummy_relying_party_value", instance.request.env["custom_relying_party"]
  end
end
