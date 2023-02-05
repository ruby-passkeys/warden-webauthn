class Warden::TestStrategyHelpersCustomization < Minitest::Test
  include WebAuthnTestHelpers

  class TestClass
    include Warden::WebAuthn::StrategyHelpers

    attr_accessor :session, :env, :params, :errors

    attr_reader :error_key

    def initialize
      self.session = {}
      self.env = {}
      self.params = {}
      self.errors = Warden::Proxy::Errors.new
    end

    def fail!(error_key)
      @error_key = error_key
    end

    def authentication_challenge_key
      'passkey_challenge'
    end

    def credential_finder_key
      'passkey_finder'
    end

    def relying_party_key
      'admin_relying_party'
    end

    def raw_credential_key
      'passkey'
    end
  end

  class TestCredentialFinder
    attr_accessor :expected_stored_credential

    def find_with_credential_id(encoded_credential_id)
      if encoded_credential_id == self.expected_stored_credential.external_id
        return expected_stored_credential
      else
        return nil
      end
    end
  end

  def setup
    @test_class = TestClass.new
  end

  def test_default_keys
    assert_equal "passkey", @test_class.raw_credential_key
    assert_equal "admin_relying_party", @test_class.relying_party_key
    assert_equal "passkey_finder", @test_class.credential_finder_key
    assert_equal "passkey_challenge", @test_class.authentication_challenge_key
  end

  def test_successful_parsed_credential
    client = fake_client
    credential = client.create

    @test_class.params = {"passkey" => credential.to_json }

    assert_equal credential, @test_class.parsed_credential
  end

  def test_missing_parsed_credential
    assert_nil @test_class.parsed_credential
    assert_equal [:missing], @test_class.errors.on(:credential)
  end

  def test_parsed_credential_parse_error
    @test_class.params = {"passkey" => "blah" }
    assert_nil @test_class.parsed_credential
    assert_equal [:json_error], @test_class.errors.on(:credential)
  end

  def test_raw_credential
    client = fake_client
    credential = client.create
    credential_json = credential.to_json

    @test_class.params = {"passkey" => credential_json }

    assert_equal credential_json, @test_class.raw_credential
  end

  def test_delete_authentication_challenge
    @test_class.session["passkey_challenge"] = "abcd1234"

    @test_class.delete_authentication_challenge

    assert_nil @test_class.session["passkey_challenge"]
  end

  def test_authentication_challenge
    challenge = "abcd1234"
    @test_class.session["passkey_challenge"] = challenge

    assert_equal challenge, @test_class.authentication_challenge
  end

  def test_credential_finder
    credential_finder = TestCredentialFinder.new
    @test_class.env['passkey_finder'] = credential_finder
    assert_equal credential_finder, @test_class.credential_finder
  end

  def test_relying_party
    relying_party = example_relying_party
    @test_class.env['admin_relying_party'] = relying_party
    assert_equal relying_party, @test_class.relying_party
  end

  def test_webauthn_error_key
    expected_pairs = [
      {error_class: WebAuthn::AttestationStatement::FormatNotSupportedError, error_key: :webauthn_attestation_statement_format_not_supported},
      {error_class: WebAuthn::PublicKey::UnsupportedAlgorithm, error_key: :webauthn_public_key_unsupported_algorithm},
      {error_class: WebAuthn::AttestationStatement::UnsupportedAlgorithm, error_key: :webauthn_attestation_statement_unsupported_algorithm},
      {error_class: WebAuthn::UserVerifiedVerificationError, error_key: :webauthn_user_verified_verification_error},
      {error_class: WebAuthn::ChallengeVerificationError, error_key: :webauthn_challenge_verification_error},
      {error_class: WebAuthn::VerificationError, error_key: :webauthn_verification_error},
      {error_class: WebAuthn::ClientDataMissingError, error_key: :webauthn_client_data_missing},
      {error_class: WebAuthn::AuthenticatorDataFormatError, error_key: :webauthn_authenticator_data_format},
      {error_class: WebAuthn::AttestedCredentialDataFormatError, error_key: :webauthn_attested_credential_data_format},
      {error_class: WebAuthn::RootCertificateFinderNotSupportedError, error_key: :webauthn_root_certificate_finder_not_supported},
      {error_class: WebAuthn::SignCountVerificationError, error_key: :webauthn_sign_count_verification_error},
      {error_class: WebAuthn::Error, error_key: :webauthn_generic_error},
    ]

    expected_pairs.each do |pair|
      error_class = pair[:error_class]
      error_key = pair[:error_key]

      exception_instance = error_class.new

      assert_equal error_key, @test_class.webauthn_error_key(exception: exception_instance), error_class
    end
  end

  def test_verify_authentication_and_find_stored_credential_success
    relying_party = example_relying_party
    client = fake_client
    credential = create_credential(client: client, relying_party: relying_party)

    stored_credential = OpenStruct.new(external_id: Base64.strict_encode64(credential.id), public_key: relying_party.encoder.encode(credential.public_key))

    raw_challenge = relying_party.options_for_authentication(user_verification: "required").challenge

    assertion = assertion_from_client(client: client, challenge: raw_challenge, user_verified: true)

    credential_finder = TestCredentialFinder.new
    credential_finder.expected_stored_credential = stored_credential

    @test_class.env['passkey_finder'] = credential_finder
    @test_class.env['admin_relying_party'] = relying_party

    @test_class.session["passkey_challenge"] = raw_challenge

    @test_class.params["passkey"] = assertion.to_json

    assert_equal stored_credential, @test_class.verify_authentication_and_find_stored_credential
    assert_nil @test_class.error_key
  end

  def test_verify_authentication_and_find_stored_credential_user_not_verified
    relying_party = example_relying_party
    client = fake_client
    credential = create_credential(client: client, relying_party: relying_party)

    stored_credential = OpenStruct.new(external_id: Base64.strict_encode64(credential.id), public_key: relying_party.encoder.encode(credential.public_key))

    raw_challenge = relying_party.options_for_authentication(user_verification: "required").challenge

    assertion = assertion_from_client(client: client, challenge: raw_challenge, user_verified: false)

    credential_finder = TestCredentialFinder.new
    credential_finder.expected_stored_credential = stored_credential

    @test_class.env['passkey_finder'] = credential_finder
    @test_class.env['admin_relying_party'] = relying_party

    @test_class.session["passkey_challenge"] = raw_challenge

    @test_class.params["passkey"] = assertion.to_json

    assert_nil @test_class.verify_authentication_and_find_stored_credential
    assert_equal :webauthn_user_verified_verification_error, @test_class.error_key
  end

  def test_verify_authentication_and_find_stored_credential_bad_challenge
    relying_party = example_relying_party
    client = fake_client
    credential = create_credential(client: client, relying_party: relying_party)

    stored_credential = OpenStruct.new(external_id: Base64.strict_encode64(credential.id), public_key: relying_party.encoder.encode(credential.public_key))

    raw_challenge = relying_party.options_for_authentication(user_verification: "required").challenge

    assertion = assertion_from_client(client: client, challenge: encode_challenge, user_verified: true)

    credential_finder = TestCredentialFinder.new
    credential_finder.expected_stored_credential = stored_credential

    @test_class.env['passkey_finder'] = credential_finder
    @test_class.env['admin_relying_party'] = relying_party

    @test_class.session["passkey_challenge"] = raw_challenge

    @test_class.params["passkey"] = assertion.to_json

    assert_nil @test_class.verify_authentication_and_find_stored_credential
    assert_equal :webauthn_challenge_verification_error, @test_class.error_key
  end
end