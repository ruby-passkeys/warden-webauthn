# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"

class Warden::TestRegistrationHelpers < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::RegistrationHelpers

    attr_accessor :session, :params

    def initialize
      self.session = {}
      self.params = {}
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
    assert_equal ({}), options_for_registration.extensions
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
    assert_equal ({}), options_for_registration.extensions
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
    assert_equal ({}), options_for_registration.extensions
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

  def test_verify_registration_success
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: true)

    @test_class.params = {"credential" => JSON.generate(raw_credential)}
    webauthn_credential = @test_class.verify_registration(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredentialWithAttestation, webauthn_credential

    assert_equal raw_credential["id"], webauthn_credential.id
    refute_nil webauthn_credential.public_key
    assert_equal 0, webauthn_credential.sign_count

    assert_nil @test_class.session["current_webauthn_registration_challenge"]
  end

  def test_verify_registration_user_not_verified
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: false)

    @test_class.params = {"credential" => JSON.generate(raw_credential)}

    assert_raises WebAuthn::UserVerifiedVerificationError do
      @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["current_webauthn_registration_challenge"]
  end

  def test_verify_registration_bad_challenge
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: "blah", user_verified: true)

    @test_class.params = {"credential" => JSON.generate(raw_credential)}
    assert_raises WebAuthn::ChallengeVerificationError do
      webauthn_credential = @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["current_webauthn_registration_challenge"]
  end

  def test_verify_registration_bad_relying_party
    relying_party = example_relying_party
    other_relying_party = example_relying_party(options: {id: "other.party"})
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = other_relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: true, rp_id: "other.party")

    @test_class.params = {"credential" => JSON.generate(raw_credential)}

    assert_raises WebAuthn::RpIdVerificationError do
      @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["current_webauthn_registration_challenge"]
  end


  def test_default_registration_challenge_key
    assert_equal "current_webauthn_registration_challenge", @test_class.registration_challenge_key
  end

  def test_default_raw_credential_key
    assert_equal "credential", @test_class.raw_credential_key
  end

  def test_raw_credential
    client = fake_client
    credential = client.create
    credential_json = credential.to_json

    @test_class.params = {"credential" => credential_json }

    assert_equal credential_json, @test_class.raw_credential
  end

  def test_successful_parsed_credential
    client = fake_client
    credential = client.create

    @test_class.params = {"credential" => credential.to_json }

    assert_equal credential, @test_class.parsed_credential
  end

  def test_missing_parsed_credential_raises_error
    assert_raises TypeError do
      @test_class.parsed_credential
    end
  end

  def test_bad_value_parsed_credential_raises_error
    @test_class.params = {"credential" => "blah" }
    assert_raises JSON::ParserError do
      @test_class.parsed_credential
    end
  end

  def test_delete_registration_challenge
    @test_class.session["current_webauthn_registration_challenge"] = "abcd1234"

    @test_class.delete_registration_challenge

    assert_nil @test_class.session["current_webauthn_registration_challenge"]
  end

  def test_registration_challenge
    challenge = "abcd1234"
    @test_class.session["current_webauthn_registration_challenge"] = challenge

    assert_equal challenge, @test_class.registration_challenge
  end
end

class Warden::TestRegistrationHelpersCustomChallengeKey < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::RegistrationHelpers

    attr_accessor :session, :params

    def initialize
      self.session = {}
      self.params = {}
    end

    def registration_challenge_key
      "custom_key"
    end

    def raw_credential_key
      "passkey"
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
    assert_equal ({}), options_for_registration.extensions
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
    assert_equal ({}), options_for_registration.extensions
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
    assert_equal ({}), options_for_registration.extensions
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

  def test_verify_registration_success
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: true)

    @test_class.params = {"passkey" => JSON.generate(raw_credential)}
    webauthn_credential = @test_class.verify_registration(relying_party: relying_party)

    assert_kind_of WebAuthn::PublicKeyCredentialWithAttestation, webauthn_credential

    assert_equal raw_credential["id"], webauthn_credential.id
    refute_nil webauthn_credential.public_key
    assert_equal 0, webauthn_credential.sign_count

    assert_nil @test_class.session["custom_key"]
  end

  def test_verify_registration_user_not_verified
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: false)

    @test_class.params = {"passkey" => JSON.generate(raw_credential)}

    assert_raises WebAuthn::UserVerifiedVerificationError do
      @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["custom_key"]
  end

  def test_verify_registration_bad_challenge
    relying_party = example_relying_party
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: "blah", user_verified: true)

    @test_class.params = {"passkey" => JSON.generate(raw_credential)}
    assert_raises WebAuthn::ChallengeVerificationError do
      webauthn_credential = @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["custom_key"]
  end

  def test_verify_registration_bad_relying_party
    relying_party = example_relying_party
    other_relying_party = example_relying_party(options: {id: "other.party"})
    authenticator = fake_authenticator
    client = fake_client(authenticator: authenticator)

    options_for_registration = other_relying_party.options_for_registration(
      user: {id: WebAuthn.generate_user_id, name: "Test1234"},
      authenticator_selection: { user_verification: "required" }
    )

    @test_class.store_challenge_in_session(options_for_registration: options_for_registration)

    raw_credential = client.create(challenge: options_for_registration.challenge, user_verified: true, rp_id: "other.party")

    @test_class.params = {"passkey" => JSON.generate(raw_credential)}

    assert_raises WebAuthn::RpIdVerificationError do
      @test_class.verify_registration(relying_party: relying_party)
    end

    assert_nil @test_class.session["custom_key"]
  end

  def test_registration_challenge_key
    assert_equal "custom_key", @test_class.registration_challenge_key
  end

  def test_default_raw_credential_key
    assert_equal "passkey", @test_class.raw_credential_key
  end

  def test_raw_credential
    client = fake_client
    credential = client.create
    credential_json = credential.to_json

    @test_class.params = {"passkey" => credential_json }

    assert_equal credential_json, @test_class.raw_credential
  end

  def test_successful_parsed_credential
    client = fake_client
    credential = client.create

    @test_class.params = {"passkey" => credential.to_json }

    assert_equal credential, @test_class.parsed_credential
  end

  def test_missing_parsed_credential_raises_error
    assert_raises TypeError do
      @test_class.parsed_credential
    end
  end

  def test_bad_value_parsed_credential_raises_error
    @test_class.params = {"passkey" => "blah" }
    assert_raises JSON::ParserError do
      @test_class.parsed_credential
    end
  end

  def test_delete_registration_challenge
    @test_class.session["custom_key"] = "abcd1234"

    @test_class.delete_registration_challenge

    assert_nil @test_class.session["custom_key"]
  end

  def test_registration_challenge
    challenge = "abcd1234"
    @test_class.session["custom_key"] = challenge

    assert_equal challenge, @test_class.registration_challenge
  end
end