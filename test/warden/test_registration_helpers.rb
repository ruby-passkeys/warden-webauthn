# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"

class Warden::TestRegistrationHelpers < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::RegistrationHelpers

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
    user_details = {name: "Test User", id: WebAuthn.generate_user_id}
    options_for_registration = relying_party.options_for_registration(user: user_details, authenticator_selection: { user_verification: "required" })

    challenge = options_for_registration.challenge

    refute_nil challenge

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    assert_equal challenge, @test_class.session["current_webauthn_registration_challenge"]
  end

  def test_generate_registration_options
    relying_party = example_relying_party
    user_details = {name: "Test User", id: WebAuthn.generate_user_id}
    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details)

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_nil options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_overrides
    relying_party = example_relying_party
    extensions = { appid: "test.test" }
    exclude = ["abcd1234", "aa33444"]

    expected_exclude_credentials = [
      {type: "public-key", id: "abcd1234"},
      {type: "public-key", id: "aa33444"},
    ]

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details, exclude: exclude, options: {extensions: extensions})

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_nil options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal exclude, options_for_registration.exclude
    assert_equal extensions, options_for_registration.extensions
    assert_equal expected_exclude_credentials, options_for_registration.exclude_credentials

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_customized_relying_party_id
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details)

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_equal relying_party_id, options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_customized_relying_party_id_and_options
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details, options: {authenticator_selection: {user_verification: "preferred"}})

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_equal relying_party_id, options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "preferred"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_default_registration_challenge_key
    assert_equal "current_webauthn_registration_challenge", @test_class.registration_challenge_key
  end
end

class Warden::TestRegistrationHelpersCustomChallengeKey < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::RegistrationHelpers

    attr_accessor :session

    def initialize
      self.session = {}
    end

    def registration_challenge_key
      "custom_key"
    end
  end

  def setup
    @test_class = TestClass.new
  end

  def test_store_challenge_in_session
    relying_party = example_relying_party
    user_details = {name: "Test User", id: WebAuthn.generate_user_id}
    options_for_registration = relying_party.options_for_registration(user: user_details, authenticator_selection: {user_verification: "required"})

    challenge = options_for_registration.challenge

    refute_nil challenge

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    assert_equal challenge, @test_class.session["custom_key"]
  end

  def test_generate_registration_options
    relying_party = example_relying_party
    user_details = {name: "Test User", id: WebAuthn.generate_user_id}
    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details)

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_nil options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_overrides
    relying_party = example_relying_party
    extensions = { appid: "test.test" }
    exclude = ["abcd1234", "aa33444"]

    expected_exclude_credentials = [
      {type: "public-key", id: "abcd1234"},
      {type: "public-key", id: "aa33444"},
    ]

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details, exclude: exclude, options: {extensions: extensions})

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_nil options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal exclude, options_for_registration.exclude
    assert_equal extensions, options_for_registration.extensions
    assert_equal expected_exclude_credentials, options_for_registration.exclude_credentials

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_customized_relying_party_id
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details)

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_equal relying_party_id, options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "required"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_generate_registration_options_with_customized_relying_party_id_and_options
    relying_party_id = "test.test"
    relying_party = example_relying_party(options: {id: relying_party_id})

    user_details = {name: "Test User", id: WebAuthn.generate_user_id}

    options_for_registration = @test_class.generate_registration_options(relying_party: relying_party, user_details: user_details, options: {authenticator_selection: {user_verification: "preferred"}})

    assert_kind_of WebAuthn::PublicKeyCredential::CreationOptions, options_for_registration
    assert_empty options_for_registration.exclude
    assert_empty options_for_registration.exclude_credentials
    assert_nil options_for_registration.extensions
    assert_equal relying_party_id, options_for_registration.rp.id

    assert_equal 120_000, options_for_registration.timeout
    assert_equal relying_party, options_for_registration.relying_party

    assert_equal ({user_verification: "preferred"}), options_for_registration.authenticator_selection

    assert_kind_of WebAuthn::PublicKeyCredential::UserEntity, options_for_registration.user

    assert_equal "Test User", options_for_registration.user.name
    assert_equal "Test User", options_for_registration.user.display_name
    refute_nil options_for_registration.user.id
    refute_nil options_for_registration.challenge
  end

  def test_default_registration_challenge_key
    assert_equal "custom_key", @test_class.registration_challenge_key
  end
end