# Omniauth Swedbank

Omniauth strategy for using Swedbank as an authentication service provider.

Supported Ruby versions: 2.7+

## Related projects

- [omniauth-citadele](https://github.com/mitigate-dev/omniauth-citadele) - strategy for authenticating with Citadele
- [omniauth-dnb](https://github.com/mitigate-dev/omniauth-dnb) - strategy for authenticating with DNB
- [omniauth-nordea](https://github.com/mitigate-dev/omniauth-nordea) - strategy for authenticating with Nordea
- [omniauth-seb-elink](https://github.com/mitigate-dev/omniauth-seb-elink) - strategy for authenticating with SEB

## Installation

Add these lines to your application's Gemfile (omniauth-rails_csrf_protection is required if using Rails):

    gem 'omniauth-rails_csrf_protection'
    gem 'omniauth-swedbank'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-rails_csrf_protection omniauth-swedbank

## v009 Migration

**Swedbank will shut down banklink protocol v008 on 2026-06-02.** See [Migration Guide](docs/migration_008_to_009.md) for details.

## Usage

Here's a quick example, adding the middleware to a Rails app
in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :swedbank,
    File.read("path/to/private.key"),
    File.read("path/to/bank.crt"),
    ENV['SWEDBANK_SND_ID'],
    ENV['SWEDBANK_REC_ID'],
    version: '009'
end
```

The `version` option defaults to `'008'` for backward compatibility. Set it to `'009'` when you're ready to migrate (requires a new bank certificate from [banklink.swedbank.com](https://banklink.swedbank.com/public/resources/bank-certificates/009)).

## Auth Hash

### v009

```ruby
{
  provider: 'swedbank',
  uid: '374042-80367',
  info: {
    full_name: 'ARNIS RAITUMS',
    country: 'LV'
  },
  extra: {
    raw_info: {
      VK_SERVICE: '3013',
      VK_VERSION: '009',
      VK_DATETIME: '2026-04-29T12:00:00+0300',
      VK_SND_ID: 'SWEDBANK_LV',
      VK_REC_ID: 'MPLMT',
      VK_NONCE: '20170425114529204413',
      VK_USER_NAME: 'ARNIS RAITUMS',
      VK_USER_ID: '374042-80367',
      VK_COUNTRY: 'LV',
      VK_OTHER: '',
      VK_TOKEN: '7',
      VK_RID: '',
      VK_MAC: 'qrEMRf6YV...',
      VK_ENCODING: 'UTF-8'
    }
  }
}
```

### v008 (deprecated)

```ruby
{
  provider: 'swedbank',
  uid: '374042-80367',
  info: {
    full_name: 'ARNIS RAITUMS'
  },
  extra: {
    raw_info: {
      VK_SERVICE: '3003',
      VK_VERSION: '008',
      VK_SND_ID: 'HP',
      VK_REC_ID: 'MPLMT',
      VK_NONCE: '20170425114529204413',
      VK_INFO: 'ISIK:090482-12549;NIMI:DACE ĀBOLA',
      VK_MAC: 'qrEMRf6YV...',
      VK_ENCODING: 'UTF-8'
    }
  }
}
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
