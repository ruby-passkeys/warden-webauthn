# frozen_string_literal: true

require_relative "webauthn/version"
require_relative "webauthn/strategy_helpers"
require_relative "webauthn/strategy"
require_relative "webauthn/authentication_initiation_helpers"

module Warden
  module WebAuthn
    class Error < StandardError; end
    # Your code goes here...
  end
end
