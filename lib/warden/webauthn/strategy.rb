# frozen_string_literal: true

require "warden"

module Warden
  module WebAuthn
    class Strategy < Warden::Strategies::Base
      include Warden::WebAuthn::StrategyHelpers

      # rubocop:disable Lint/UnreachableCode
      def valid?
        return true unless parsed_credential.nil?

        fail(:credential_missing_or_could_not_be_parsed)
        false
      end
      # rubocop:enable Lint/UnreachableCode

      def authenticate!
        stored_credential = verify_authentication_and_find_stored_credential

        return if stored_credential.nil?

        success!(stored_credential.user)
      end
    end
  end
end
