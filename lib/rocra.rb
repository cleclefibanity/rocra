require 'openssl'

require "rocra/version"

class Rocra

  class << self

    # This method generates an OCRA HOTP value for the given set of
    # parameters.
    #
    # @param ocraSuite    the OCRA Suite
    # @param key          the shared secret, HEX encoded
    # @param counter      the counter that changes
    #                     on a per use basis,
    #                     HEX encoded
    # @param question     the challenge question, HEX encoded
    # @param password     a password that can be used,
    #                     HEX encoded
    # @param sessionInformation
    #                     Static information that identifies the
    #                     current session, Hex encoded
    # @param timestamp    a value that reflects a time
    #
    # @return A numeric String in base 10 that includes
    # {@link truncationDigits} digits
    def generate(ocra_suite, key, counter, question, password, session_information, timestamp)

      code_digits = 0
      crypto = ""
      result = nil
      ocra_suite_length = ocra_suite.length
      counter_length = 0
      question_length = 0
      password_length = 0

      session_information_length = 0
      timestamp_length = 0

      # How many digits should we return
      components = ocra_suite.split(':')
      cryptoFunction = components[1]
      dataInput = components[2].downcase # lower here so we can do case insensitive comparisons

      crypto = 'sha1'   if cryptoFunction.downcase.include?('sha1')
      crypto = 'sha256' if cryptoFunction.downcase.include?('sha256')
      crypto = 'sha512' if cryptoFunction.downcase.include?('sha512')

      code_digits = cryptoFunction.split('-').last

      # The size of the byte array message to be encrypted

      # Counter
      if dataInput[0,1] == "c"
        # Fix the length of the HEX string
        counter_length=8
        counter = counter.rjust(16, '0')
      end

      # Question
      if dataInput[0,1] == "q" || dataInput.include?('-q')
        question = question.ljust(256, '0')
        question_length = 128
      end

      # Password
      if dataInput.include?("psha1")
        password = password.ljust(40, '0')
        password_length = 20
      end

      if dataInput.include?("psha256")
        password = password.ljust(64, '0')
        password_length = 32
      end

      if dataInput.include?("psha512")
        password = password.ljust(128, '0')
        password_length = 64
      end

      # session_information
      if dataInput.include?("s064")
        session_information = session_information.rjust(128, '0')
        session_information_length = 64
      end

      if dataInput.include?("s128")
        session_information = session_information.rjust(256, '0')
        session_information_length = 128
      end

      if dataInput.include?("s256")
        session_information = session_information.rjust(512, '0')
        session_information_length = 256
      end

      if dataInput.include?("s512")
        session_information = session_information.rjust(128, '0')
        session_information_length = 64
      end

      # TimeStamp
      if dataInput[0,1] == "t" || dataInput.include?("-t")
        timestamp = timestamp.rjust(16, '0')
        timestamp_length = 8
      end

      # Put the bytes of "ocra_suite" parameters into the message
      length = ocra_suite_length +
        counter_length +
        question_length +
        password_length +
        session_information_length +
        timestamp_length + 1
      msg = "\0" * length
      msg[0, ocra_suite.length] = ocra_suite

      # Delimiter
      # msg[ocra_suite.length] = hex2str("0")

      # Put the bytes of "Counter" to the message
      # Input is HEX encoded
      if counter_length > 0
        pos = ocra_suite_length + 1
        msg[pos, counter.length] = hex2str(counter)
      end

      # Put the bytes of "question" to the message
      # Input is text encoded
      if question_length > 0
        pos = ocra_suite_length + 1 + counter_length
        msg[pos, question.length] = hex2str(question)
      end

      # Put the bytes of "password" to the message
      # Input is HEX encoded
      if password_length > 0
        pos = ocra_suite_length + 1 + counter_length + question_length
        msg[pos, password.length] = hex2str(password)
      end

      # Put the bytes of "session_information" to the message
      # Input is text encoded
      if session_information_length > 0
        pos = ocra_suite_length + 1 + counter_length + question_length + password_length
        msg[pos, session_information.length] = hex2str(session_information)
      end

      # Put the bytes of "time" to the message
      # Input is text value of minutes
      if timestamp_length > 0
        pos = ocra_suite_length + 1 + counter_length + question_length +
          password_length + session_information_length
        msg[pos, timestamp.length] = hex2str(timestamp)
      end

      byteKey = hex2str(key)
      hash = hmac_sha1(crypto, byteKey, msg)
      oath_truncate(hash, code_digits)

    end

    private

    # Truncate a result to a certain length
    #
    # - hash is a hex string
    def oath_truncate(hash, length = 6)

      # Convert to array of decimals
      hmac_result = hash.scan(/../).map { |e| e.hex }

      # Find offset
      offset = hmac_result.last & 0xf

      v =
        (hmac_result[offset + 0] & 0x7f) << 24 |
        (hmac_result[offset + 1] & 0xff) << 16 |
        (hmac_result[offset + 2] & 0xff) << 8 |
        (hmac_result[offset + 3] & 0xff)

      r = v % 10 ** length.to_i

      "%0#{length}d" % r
    end

    # This method uses the hmac_hash function to provide the crypto
    # algorithm.
    # HMAC computes a Hashed Message Authentication Code with the
    # crypto hash algorithm as a parameter.
    #
    # @param String crypto     the crypto algorithm (sha1, sha256 or sha512)
    # @param String keyBytes   the bytes to use for the HMAC key
    # @param String text       the message or text to be authenticated.
    #
    def hmac_sha1(crypto, keyBytes, text)
      digest = OpenSSL::Digest::Digest.new(crypto)
      str2hex(OpenSSL::HMAC.digest(digest, keyBytes, text))
    end

    # This method converts HEX string to Byte[]
    #
    # @param String hex   the HEX string
    #
    # @return String a string with raw bytes
    def hex2str(hex)
      [hex].pack('H*')
    end

    def str2hex(str)
      str.unpack('H*').first
    end

  end

end
