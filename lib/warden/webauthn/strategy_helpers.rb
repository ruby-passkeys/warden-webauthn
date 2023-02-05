# frozen_string_literal: true
require 'webauthn'

module Warden
  module WebAuthn
    module StrategyHelpers

      def verify_authentication_and_find_stored_credential
        begin
          _ , stored_credential = relying_party.verify_authentication(
            parsed_credential, authentication_challenge, user_verification: true
          ) do |webauthn_credential|
            credential_finder.find_with_credential_id(Base64.strict_encode64(webauthn_credential.raw_id))
          end

          delete_authentication_challenge

          if stored_credential.nil?
            errors.add(:stored_credential, :not_found)
            fail!
            return
          end

          return stored_credential
        rescue WebAuthn::Error => e
          fail!(webauthn_error_key(exception: e))
        end
      end

      def webauthn_error_key(exception:)
        case exception
        when WebAuthn::AttestationStatement::FormatNotSupportedError
          return :webauthn_attestation_statement_format_not_supported
        when WebAuthn::PublicKey::UnsupportedAlgorithm
          return :webauthn_public_key_unsupported_algorithm
        when WebAuthn::AttestationStatement::UnsupportedAlgorithm
          return :webauthn_attestation_statement_unsupported_algorithm
        when WebAuthn::VerificationError
          return :webauthn_verification_error
        when WebAuthn::ClientDataMissingError
          return :webauthn_client_data_missing
        when WebAuthn::AuthenticatorDataFormatError
          return :webauthn_authenticator_data_format
        when WebAuthn::AttestedCredentialDataFormatError
          return :webauthn_attested_credential_data_format
        when WebAuthn::RootCertificateFinderNotSupportedError
          return :webauthn_root_certificate_finder_not_supported
        when WebAuthn::SignCountVerificationError
          return :webauthn_sign_count_verification_error
        when WebAuthn::Error
          return :webauthn_generic_error
        end
      end

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
        if raw_credential.nil? || raw_credential.try(:empty?)
          errors.add(:credential, :missing)
          return nil
        end

        begin
          return JSON.parse(raw_credential)
        rescue JSON::JSONError
          errors.add(:credential, :json_error)
        end
      end

      def authentication_challenge_key
        'current_webauthn_authentication_challenge'
      end

      def credential_finder_key
        'warden.webauthn.credential_finder'
      end

      def relying_party_key
        'warden.webauthn.relying_party'
      end

      def raw_credential_key
        'credential'
      end
    end
  end
end