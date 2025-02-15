# frozen_string_literal: true

require_relative "test_helper"

class IOLensTest < Minitest::Test
  def test_lens_writes
    input = Random.bytes(48)
    (1..input.bytesize).each do |write_size|
      ranges = [
        0..0,
        0...1,
        1..1,
        1...2,
        43..120,
        14..,
        ..14
      ]
      ranges.each do |test_range|
        test_io = StringIO.new.binmode
        readable = StringIO.new(input).binmode
        lens = BlockCipherKit::IOLens.new(test_io, test_range)
        while (chunk = readable.read(write_size))
          lens.write(chunk)
        end
        assert_equal input[test_range].bytesize, test_io.size
        assert_equal input[test_range], test_io.string
      end
    end
  end
end
