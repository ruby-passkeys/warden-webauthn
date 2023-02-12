# frozen_string_literal: true

module Warden
  module WebAuthn
    # Helper methods for generating & storing authentication challenges
    module AuthenticationInitiationHelpers
      def generate_authentication_options(relying_party:, options: {})
        relying_party.options_for_authentication(**{
          user_verification: "required"
        }.merge(options))
      end

      def store_challenge_in_session(options_for_authentication:)
        session[authentication_challenge_key] = options_for_authentication.challenge
      end

      def authentication_challenge_key
        "current_webauthn_authentication_challenge"
      end
    end
  end
end
