# frozen_string_literal: true

require "webauthn"

module Warden
  module WebAuthn
    module StrategyHelpers
      class NoStoredCredentialFound < StandardError; end

      # rubocop:disable Metrics/MethodLength
      def verify_authentication_and_find_stored_credential
        _, stored_credential = relying_party.verify_authentication(
          parsed_credential, authentication_challenge, user_verification: true
        ) do |webauthn_credential|
          x = credential_finder.find_with_credential_id(Base64.strict_encode64(webauthn_credential.raw_id))
          raise NoStoredCredentialFound if x.nil?

          x
        end

        stored_credential
      rescue ::WebAuthn::Error => e
        fail!(webauthn_error_key(exception: e))
        nil
      rescue NoStoredCredentialFound
        errors.add(:stored_credential, :not_found)
        fail!(:stored_credential_not_found)
        nil
      ensure
        delete_authentication_challenge
      end
      # rubocop:enable Metrics/MethodLength

      # rubocop:disable Metrics/CyclomaticComplexity
      # rubocop:disable Metrics/MethodLength
      def webauthn_error_key(exception:)
        case exception
        when ::WebAuthn::AttestationStatement::FormatNotSupportedError
          :webauthn_attestation_statement_format_not_supported
        when ::WebAuthn::PublicKey::UnsupportedAlgorithm
          :webauthn_public_key_unsupported_algorithm
        when ::WebAuthn::AttestationStatement::UnsupportedAlgorithm
          :webauthn_attestation_statement_unsupported_algorithm
        when ::WebAuthn::UserVerifiedVerificationError
          :webauthn_user_verified_verification_error
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
        end
      end
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/MethodLength

      def relying_party
        env[relying_party_key]
      end

      def credential_finder
        env[credential_finder_key]
      end

      def authentication_challenge
        session[authentication_challenge_key]
      end

      def delete_authentication_challenge
        session.delete(authentication_challenge_key)
      end

      def raw_credential
        params[raw_credential_key]
      end

      def parsed_credential
        if raw_credential.nil? || raw_credential.empty?
          errors.add(:credential, :missing)
          return nil
        end

        begin
          JSON.parse(raw_credential)
        rescue JSON::JSONError
          errors.add(:credential, :json_error)
          nil
        end
      end

      def authentication_challenge_key
        "current_webauthn_authentication_challenge"
      end

      def credential_finder_key
        "warden.webauthn.credential_finder"
      end

      def relying_party_key
        "warden.webauthn.relying_party"
      end

      def raw_credential_key
        "credential"
      end
    end
  end
end
