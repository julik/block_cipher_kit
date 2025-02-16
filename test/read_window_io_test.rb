# frozen_string_literal: true

require_relative "test_helper"

class BlockCipherKit::ReadWindowTest < Minitest::Test
  def test_read_window
    text = "mary had a little lamb, riding on a pony"

    window = BlockCipherKit::ReadWindowIO.new(StringIO.new(text), 0, 0)
    assert_nil window.read(1)

    window = BlockCipherKit::ReadWindowIO.new(StringIO.new(text), 0, 4)
    assert_equal "m", window.read(1)
    assert_equal "a", window.read(1)
    assert_equal "ry", window.read(2)
    assert_nil window.read(1)

    io = StringIO.new(text)
    window = BlockCipherKit::ReadWindowIO.new(io, 0, 4)
    assert_equal 0, window.pos
    assert_equal "m", window.read(1)
    assert_equal 1, window.pos

    io.seek(0)
    assert_equal "a", window.read(1)
    assert_equal 0, window.seek(0)

    window = BlockCipherKit::ReadWindowIO.new(StringIO.new(text), 8, 23)
    assert_equal " a l", window.read(4)
    assert_equal "ittle la", window.read(8)

    window = BlockCipherKit::ReadWindowIO.new(StringIO.new(text), 8, text.bytesize)
    assert_equal " a little lamb, riding on a pony", window.read(400)
    assert_nil window.read(1)
  end
end
