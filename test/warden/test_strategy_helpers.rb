# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"

class Warden::TestStrategyHelpers < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::StrategyHelpers

    attr_accessor :session, :env, :params, :errors

    def initialize
      self.session = {}
      self.env = {}
      self.params = {}
      self.errors = Warden::Proxy::Errors.new
    end
  end

  def setup
    @test_class = TestClass.new
  end

  def test_default_keys
    assert_equal "credential", @test_class.raw_credential_key
    assert_equal "warden.webauthn.relying_party", @test_class.relying_party_key
    assert_equal "warden.webauthn.credential_finder", @test_class.credential_finder_key
    assert_equal "current_webauthn_authentication_challenge", @test_class.authentication_challenge_key
  end

  def test_successful_parsed_credential
    client = fake_client
    credential = client.create

    @test_class.params = {"credential" => credential.to_json }

    assert_equal credential, @test_class.parsed_credential
  end

  def test_missing_parsed_credential
    assert_nil @test_class.parsed_credential
    assert_equal [:missing], @test_class.errors.on(:credential)
  end

  def test_parsed_credential_parse_error
    @test_class.params = {"credential" => "blah" }
    assert_nil @test_class.parsed_credential
    assert_equal [:json_error], @test_class.errors.on(:credential)
  end
end