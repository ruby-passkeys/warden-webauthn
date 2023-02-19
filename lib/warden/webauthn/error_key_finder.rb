# frozen_string_literal: true

module Warden
  module WebAuthn
    # Helper method for generating a symbol based on the WebAuthn::Error
    class ErrorKeyFinder
      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/MethodLength
      def self.webauthn_error_key(exception:)
        case exception
        when ::WebAuthn::AttestationStatement::FormatNotSupportedError
          :webauthn_attestation_statement_format_not_supported
        when ::WebAuthn::PublicKey::UnsupportedAlgorithm
          :webauthn_public_key_unsupported_algorithm
        when ::WebAuthn::AttestationStatement::UnsupportedAlgorithm
          :webauthn_attestation_statement_unsupported_algorithm
        when ::WebAuthn::UserVerifiedVerificationError
          :webauthn_user_verified_verification_error
        when ::WebAuthn::OriginVerificationError
          :webauthn_origin_verification_error
        when ::WebAuthn::ChallengeVerificationError
          :webauthn_challenge_verification_error
        when ::WebAuthn::SignCountVerificationError
          :webauthn_sign_count_verification_error
        when ::WebAuthn::VerificationError
          :webauthn_verification_error
        when ::WebAuthn::ClientDataMissingError
          :webauthn_client_data_missing
        when ::WebAuthn::AuthenticatorDataFormatError
          :webauthn_authenticator_data_format
        when ::WebAuthn::AttestedCredentialDataFormatError
          :webauthn_attested_credential_data_format
        when ::WebAuthn::RootCertificateFinderNotSupportedError
          :webauthn_root_certificate_finder_not_supported
        when ::WebAuthn::Error
          :webauthn_generic_error
        else
          raise RuntimeError
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/MethodLength
    end
  end
end
