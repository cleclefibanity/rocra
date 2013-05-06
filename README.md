[![Build Status](https://travis-ci.org/branch14/rocra.png?branch=master)](https://travis-ci.org/branch14/rocra)

     _ __ ___   ___ _ __ __ _
    | '__/ _ \ / __| '__/ _` |
    | | | (_) | (__| | | (_| |
    |_|  \___/ \___|_|  \__,_|

# Welcome to rocra

rocra is an OCRA (RFC 6287) implementation in Ruby.

see http://tools.ietf.org/html/rfc6287

It is based on the implementations found here https://github.com/SURFnet/ocra-implementations

## Installation

Add this line to your application's Gemfile:

    gem 'rocra'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rocra

## Usage

    suite     = 'OCRA-1:HOTP-SHA1-6:QN08' # string, mandatory
    key       = "3132333435363738393031323334353637383930" # hex, mandatory
    counter   = nil # hex, optional
    question  = '12345678'.to_i.to_s(16) # hex, mandatory
    password  = nil # hex, optional
    session   = nil # hex, optional
    timestamp = nil # optional
    
    Rocra.generate(suite, key, counter, question, password, session, timestamp)

## Specs

Run

    rspec

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

## Todo

- fix jruby issues
- make api more rubyesque
