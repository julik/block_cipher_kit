# An adapter which allows a block that accepts chunks of
# written data to be used as an IO and passed to IO.copy_stream
class BlockCipherKit::BlockWritable
  def initialize(io = nil, &blk)
    if (!io && !blk) || (io && blk)
      raise ArgumentError, "BlockWritable requires io or a block, but not both"
    end
    @io = io
    @blk = blk
  end

  def write(string)
    if string.bytesize.nonzero? && @io
      @io.write(string.b)
    elsif string.bytesize.nonzero? && @blk
      @blk.call(string.b)
    end
    string.bytesize
  end
end
