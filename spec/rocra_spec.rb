require File.expand_path('../../lib/rocra', __FILE__)

describe Rocra do

  it 'should nicely translate binary strings into hex strings' do
    Rocra.send(:str2hex, 'ab').should == '6162'
  end
 
  it 'should nicely translate hex strings into binary strings' do
    Rocra.send(:hex2str, '6162').should == 'ab'
  end

  # examples from http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
  it 'should nicely calculate hmac_sha1' do
    Rocra.send(:hmac_sha1, 'sha1', '', '').should == 'fbdb1d1b18aa6c08324b7d64b71fb76370690e1d'
    Rocra.send(:hmac_sha1, 'sha1', "key", "The quick brown fox jumps over the lazy dog").should ==
      'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9'
  end

  KEY_20 = "3132333435363738393031323334353637383930"
  KEY_32 = "3132333435363738393031323334353637383930313233343536373839303132"
  KEY_64 = "3132333435363738393031323334353637383930313233343536373839303132"+
    "3334353637383930313233343536373839303132333435363738393031323334"
  PIN_1234_HASH = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220"

  it 'should work for OCRA-1:HOTP-SHA1-6:QN08' do
    suite = "OCRA-1:HOTP-SHA1-6:QN08"
    Rocra.generate(suite, KEY_20, nil, '00000000'.to_i.to_s(16), nil, nil, nil).should == '237653'
    Rocra.generate(suite, KEY_20, nil, '11111111'.to_i.to_s(16), nil, nil, nil).should == '243178'
    Rocra.generate(suite, KEY_20, nil, '22222222'.to_i.to_s(16), nil, nil, nil).should == '653583'
    Rocra.generate(suite, KEY_20, nil, '33333333'.to_i.to_s(16), nil, nil, nil).should == '740991'
    Rocra.generate(suite, KEY_20, nil, '44444444'.to_i.to_s(16), nil, nil, nil).should == '608993'
    Rocra.generate(suite, KEY_20, nil, '55555555'.to_i.to_s(16), nil, nil, nil).should == '388898'
    Rocra.generate(suite, KEY_20, nil, '66666666'.to_i.to_s(16), nil, nil, nil).should == '816933'
    Rocra.generate(suite, KEY_20, nil, '77777777'.to_i.to_s(16), nil, nil, nil).should == '224598'
    Rocra.generate(suite, KEY_20, nil, '88888888'.to_i.to_s(16), nil, nil, nil).should == '750600'
    Rocra.generate(suite, KEY_20, nil, '99999999'.to_i.to_s(16), nil, nil, nil).should == '294470'
  end

  it 'should work with counter' do
    suite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1"
    Rocra.generate(suite, KEY_32, "0", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "65347737"
    Rocra.generate(suite, KEY_32, "1", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "86775851"
    Rocra.generate(suite, KEY_32, "2", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "78192410"
    Rocra.generate(suite, KEY_32, "3", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "71565254"
    Rocra.generate(suite, KEY_32, "4", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "10104329"
    Rocra.generate(suite, KEY_32, "5", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "65983500"
    Rocra.generate(suite, KEY_32, "6", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "70069104"
    Rocra.generate(suite, KEY_32, "7", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "91771096"
    Rocra.generate(suite, KEY_32, "8", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "75011558"
    Rocra.generate(suite, KEY_32, "9", "12345678".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "08522129"
  end

  it 'should work for OCRA-1:HOTP-SHA256-8:QN08-PSHA1' do
    suite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1"
    Rocra.generate(suite, KEY_32, nil, "00000000".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "83238735"
    Rocra.generate(suite, KEY_32, nil, "11111111".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "01501458"
    Rocra.generate(suite, KEY_32, nil, "22222222".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "17957585"
    Rocra.generate(suite, KEY_32, nil, "33333333".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "86776967"
    Rocra.generate(suite, KEY_32, nil, "44444444".to_i.to_s(16), PIN_1234_HASH, nil, nil).should == "86807031"
  end
        
  it 'should work for OCRA-1:HOTP-SHA512-8:C-QN08' do
    suite = "OCRA-1:HOTP-SHA512-8:C-QN08"
    Rocra.generate(suite, KEY_64, "00000", "00000000".to_i.to_s(16), nil, nil, nil).should == "07016083"
    Rocra.generate(suite, KEY_64, "00001", "11111111".to_i.to_s(16), nil, nil, nil).should == "63947962"
    Rocra.generate(suite, KEY_64, "00002", "22222222".to_i.to_s(16), nil, nil, nil).should == "70123924"
    Rocra.generate(suite, KEY_64, "00003", "33333333".to_i.to_s(16), nil, nil, nil).should == "25341727"
    Rocra.generate(suite, KEY_64, "00004", "44444444".to_i.to_s(16), nil, nil, nil).should == "33203315"
    Rocra.generate(suite, KEY_64, "00005", "55555555".to_i.to_s(16), nil, nil, nil).should == "34205738"
    Rocra.generate(suite, KEY_64, "00006", "66666666".to_i.to_s(16), nil, nil, nil).should == "44343969"
    Rocra.generate(suite, KEY_64, "00007", "77777777".to_i.to_s(16), nil, nil, nil).should == "51946085"
    Rocra.generate(suite, KEY_64, "00008", "88888888".to_i.to_s(16), nil, nil, nil).should == "20403879"
    Rocra.generate(suite, KEY_64, "00009", "99999999".to_i.to_s(16), nil, nil, nil).should == "31409299"
  end
  
  it 'should work for OCRA-1:HOTP-SHA512-8:QN08-T1M' do
    suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M"
    Rocra.generate(suite, KEY_64, nil, "00000000".to_i.to_s(16), nil, nil, "132d0b6").should == "95209754"
    Rocra.generate(suite, KEY_64, nil, "11111111".to_i.to_s(16), nil, nil, "132d0b6").should == "55907591"
    Rocra.generate(suite, KEY_64, nil, "22222222".to_i.to_s(16), nil, nil, "132d0b6").should == "22048402"
    Rocra.generate(suite, KEY_64, nil, "33333333".to_i.to_s(16), nil, nil, "132d0b6").should == "24218844"
    Rocra.generate(suite, KEY_64, nil, "44444444".to_i.to_s(16), nil, nil, "132d0b6").should == "36209546"
  end

end
