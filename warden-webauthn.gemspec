# frozen_string_literal: true

require_relative "lib/warden/webauthn/version"

Gem::Specification.new do |spec|
  spec.name = "warden-webauthn"
  spec.version = Warden::Webauthn::VERSION
  spec.authors = ["Thomas Cannon"]
  spec.email = ["tcannon00@gmail.com"]

  spec.summary = "A Warden Strategy for WebAuthn"
  spec.description = "A Warden Strategy for WebAuthn"
  spec.homepage = "https://github.com/ruby-passkeys/warden-webauthn"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.6.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/ruby-passkeys/warden-webauthn"
  spec.metadata["changelog_uri"] = "https://github.com/ruby-passkeys/warden-webauthn/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "warden"
  spec.add_dependency "webauthn"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
