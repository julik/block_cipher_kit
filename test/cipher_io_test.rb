# frozen_string_literal: true

require_relative "test_helper"

class CipherIOTest < Minitest::Test
  class FakeCipher
    def update(str)
      # Fail the same way as OpenSSL ciphers do on empty input
      raise ArgumentError, " data must not be empty" if str.bytesize.zero?
      str + "c"
    end
  end

  def test_writes_through_the_cipher_and_returns_correct_data
    out = StringIO.new
    cipher_io = BlockCipherKit::CipherIO.new(out, FakeCipher.new)
    assert_equal 2, cipher_io.write("ab")
    assert_equal "abc", out.string
  end

  def test_does_not_update_cipher_with_empty_strings
    fake_cipher = FakeCipher.new
    assert_raises(ArgumentError) { fake_cipher.update("") }

    out = StringIO.new
    cipher_io = BlockCipherKit::CipherIO.new(out, FakeCipher.new)
    assert_equal 0, cipher_io.write("")
    assert out.size.zero?
  end
end
