# Omniauth Swedbank

Omniauth strategy for using Swedbank as an authentication service provider.

[![Gem Version](https://badge.fury.io/rb/omniauth-swedbank.png)](http://badge.fury.io/rb/omniauth-swedbank)
[![Build Status](https://travis-ci.org/mak-it/omniauth-swedbank.svg?branch=master)](https://travis-ci.org/mak-it/omniauth-swedbank)

Supported Ruby versions: 2.2+

## Related projects

- [omniauth-dnb](https://github.com/mak-it/omniauth-dnb) - strategy for authenticating with DNB
- [omniauth-nordea](https://github.com/mak-it/omniauth-nordea) - strategy for authenticating with Nordea


## Installation

Add this line to your application's Gemfile:

    gem 'omniauth-swedbank'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-swedbank

## Usage

Here's a quick example, adding the middleware to a Rails app
in `config/initializers/omniauth.rb`:

```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  provider :swedbank,
    File.read("path/to/private.key"),
    File.read("path/to/bank.crt"),
    ENV['SWEDBANK_SND_ID'],
end
```

## Auth Hash

Here's an example Auth Hash available in `request.env['omniauth.auth']`:

```ruby
{
  provider: 'swedbank',
  uid: '374042-80367',
  info: {
    full_name: 'ARNIS RAITUMS'
  },
  extra: {
    raw_info: {
      VK_SERVICE: '2001',
      VK_VERSION: '101',
      VK_SND_ID: 'RIKOLV2X',
      VK_REC_ID: '10..',
      VK_STAMP: '20170403112855087471',
      VK_T_NO: '616365957',
      VK_PER_CODE: '374042-80367',
      VK_PER_FNAME: 'ARNIS',
      VK_PER_LNAME: 'RAITUMS',
      VK_COM_CODE: '',
      VK_COM_NAME: '',
      VK_TIME: '20170403113328',
      VK_MAC: 'SkYmH5AFI6Av ...',
      VK_LANG: 'LAT'
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
