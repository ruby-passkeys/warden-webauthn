# frozen_string_literal: true

require_relative "webauthn/version"
require_relative "webauthn/error_key_finder"
require_relative "webauthn/rack_helpers"
require_relative "webauthn/strategy_helpers"
require_relative "webauthn/strategy"
require_relative "webauthn/authentication_initiation_helpers"
require_relative "webauthn/registration_helpers"

# rubocop:disable Style/Documentation
module Warden
  module WebAuthn
  end
end
# rubocop:enable Style/Documentation
