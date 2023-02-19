# frozen_string_literal: true

require "test_helper"
require "test_helper/webauthn_test_helpers"

class Warden::TestErrorKeyFinder < Minitest::Test
  def test_webauthn_error_key
    expected_pairs = [
      {error_class: WebAuthn::AttestationStatement::FormatNotSupportedError, error_key: :webauthn_attestation_statement_format_not_supported},
      {error_class: WebAuthn::PublicKey::UnsupportedAlgorithm, error_key: :webauthn_public_key_unsupported_algorithm},
      {error_class: WebAuthn::AttestationStatement::UnsupportedAlgorithm, error_key: :webauthn_attestation_statement_unsupported_algorithm},
      {error_class: WebAuthn::UserVerifiedVerificationError, error_key: :webauthn_user_verified_verification_error},
      {error_class: WebAuthn::OriginVerificationError, error_key: :webauthn_origin_verification_error},
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

      assert_equal error_key, Warden::WebAuthn::ErrorKeyFinder.webauthn_error_key(exception: exception_instance), error_class
    end
  end

  def test_runtime_error_if_given_unknown_exception
    assert_raises RuntimeError do
      Warden::WebAuthn::ErrorKeyFinder.webauthn_error_key(exception: JSON::ParserError.new)
    end
  end
end