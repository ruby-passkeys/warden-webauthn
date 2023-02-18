# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"

class Warden::TestAuthenticationInitiationHelpers < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::AuthenticationInitiationHelpers

    attr_accessor :session

    def initialize
      self.session = {}
    end
  end

  def setup
    @test_class = TestClass.new
  end

  def test_store_challenge_in_session
    relying_party = example_relying_party
    options_for_authentication = relying_party.options_for_authentication(user_verification: "required")

    challenge = options_for_authentication.challenge

    refute_nil challenge

    @test_class.store_challenge_in_session(options_for_authentication: options_for_authentication)

    assert_equal challenge, @test_class.session["current_webauthn_authentication_challenge"]
  end

  def test_generate_authentication_options
    relying_party = example_relying_party
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_nil options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_overrides
    relying_party = example_relying_party
    extensions = { appid: "test.test" }
    allow = ["abcd1234", "aa33444"]

    expected_allow_credentials = [
      {type: "public-key", id: "abcd1234"},
      {type: "public-key", id: "aa33444"},
    ]

    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party, options: {allow: allow, extensions: extensions})

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal allow, options_for_authentication.allow
    assert_equal extensions, options_for_authentication.extensions
    assert_equal expected_allow_credentials, options_for_authentication.allow_credentials

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_customized_relying_party_id
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_equal relying_party_id, options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_customized_relying_party_id_and_options
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party, options: {user_verification: "preferred"})

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_equal relying_party_id, options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "preferred", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_default_authentication_challenge_key
    assert_equal "current_webauthn_authentication_challenge", @test_class.authentication_challenge_key
  end
end

class Warden::TestAuthenticationInitiationHelpersCustomChallengeKey < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::AuthenticationInitiationHelpers

    attr_accessor :session

    def initialize
      self.session = {}
    end

    def authentication_challenge_key
      "custom_key"
    end
  end

  def setup
    @test_class = TestClass.new
  end

  def test_store_challenge_in_session
    relying_party = example_relying_party
    options_for_authentication = relying_party.options_for_authentication(user_verification: "required")

    challenge = options_for_authentication.challenge

    refute_nil challenge

    @test_class.store_challenge_in_session(options_for_authentication: options_for_authentication)

    assert_equal challenge, @test_class.session["custom_key"]
  end

  def test_generate_authentication_options
    relying_party = example_relying_party
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_nil options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_overrides
    relying_party = example_relying_party
    extensions = { appid: "test.test" }
    allow = ["abcd1234", "aa33444"]

    expected_allow_credentials = [
      {type: "public-key", id: "abcd1234"},
      {type: "public-key", id: "aa33444"},
    ]

    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party, options: {allow: allow, extensions: extensions})

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal allow, options_for_authentication.allow
    assert_equal extensions, options_for_authentication.extensions
    assert_equal expected_allow_credentials, options_for_authentication.allow_credentials

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_customized_relying_party_id
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_equal relying_party_id, options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "required", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_generate_authentication_options_with_customized_relying_party_id_and_options
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})
    options_for_authentication = @test_class.generate_authentication_options(relying_party: relying_party, options: {user_verification: "preferred"})

    assert_kind_of WebAuthn::PublicKeyCredential::RequestOptions, options_for_authentication
    assert_nil options_for_authentication.allow
    assert_empty options_for_authentication.allow_credentials
    assert_equal ({}), options_for_authentication.extensions
    assert_equal relying_party_id, options_for_authentication.rp_id

    assert_equal 120_000, options_for_authentication.timeout
    assert_equal relying_party, options_for_authentication.relying_party

    assert_equal "preferred", options_for_authentication.user_verification
    refute_nil options_for_authentication.challenge
  end

  def test_default_authentication_challenge_key
    assert_equal "custom_key", @test_class.authentication_challenge_key
  end
end