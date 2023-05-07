# Warden::WebAuthn

This Warden strategy is a series of helper methods wrapping [webauthn-ruby](https://github.com/cedarcode/webauthn-ruby).

It can be used on its own to allow for webauthn registration/authentication, such as passkeys authentication.

There is also a lightweight devise extension that uses `Warden::WebAuthn`; if you're using Devise: [devise-passkeys](https://github.com/ruby-passkeys/devise-passkeys)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'warden-webauthn'
```

And then execute:

```sh
$ bundle install
```

Or install it yourself as:

```sh
$ gem install warden-webauthn
```


## Usage

`Warden::WebAuthn` is a series of modules that can be included wherever you need to implement WebAuthn calls. The primary modules/classes are:

* `Warden::WebAuthn::Strategy`: A subclass of `Warden::Strategies::Base`, the core strategy for WebAuthn authentication in Warden. This is the strategy you'd include in your Warden configuration
* `Warden::WebAuthn::StrategyHelpers`: Helpers that can be mixed in to any WebAuthn-related code, such as custom strategies or an app's authentication flow
* `Warden::WebAuthn::RegistrationHelpers`: Helper methods to bootstrap registration challenges for implementors
* `Warden::WebAuthn::AuthenticationInitiationHelpers`: Helper methods for generating & storing authentication challenges
* `Warden::WebAuthn::ErrorKeyFinder.webauthn_error_key(exception:)`: Helper method for generating a symbol based on the WebAuthn::Error

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/delete_registration_challenge/warden-webauthn. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/delete_registration_challenge/warden-webauthn/blob/main/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the Warden::WebAuthn project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/delete_registration_challenge/warden-webauthn/blob/main/CODE_OF_CONDUCT.md).
