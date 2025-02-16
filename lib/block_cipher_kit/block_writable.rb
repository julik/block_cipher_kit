# :nodoc:
# An adapter which allows a block that accepts chunks of
# written data to be used as an IO and passed to IO.copy_stream
class BlockCipherKit::BlockWritable
  def self.new(io = nil, &blk)
    if (!io && !blk) || (io && blk)
      raise ArgumentError, "BlockWritable requires io or a block, but not both"
    end
    # If the IO is given, it is better to just pass it through
    # as IO.copy_stream will do optimisations for native IOs like
    # File, Socket etc.
    return io if io
    super(&blk)
  end

  def initialize(&blk)
    @blk = blk
  end

  def write(string)
    @blk.call(string.b)
    string.bytesize
  end
end
