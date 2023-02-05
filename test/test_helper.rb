# frozen_string_literal: true

Bundler.require(:default, :test)
SimpleCov.start


$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "warden/webauthn"

require "minitest/autorun"
