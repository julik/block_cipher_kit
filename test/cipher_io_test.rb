# frozen_string_literal: true

require_relative "test_helper"

class CipherIOTest < Minitest::Test
  class FakeCipher
    def update(str)
      str + "c"
    end
  end

  def test_writes_through_the_cipher_and_returns_correct_data
    out = StringIO.new
    cipher_io = BlockCipherKit::CipherIO.new(out, FakeCipher.new)
    assert_equal 2, cipher_io.write("ab")
    assert_equal "abc", out.string
  end
end
