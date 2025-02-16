# Used as a stand-in for any IO-ish that responds to #read. This module is defined for YARD docs
# so that Sorbet has a proper type definition.
module StraightReadableIO
  # @param n[Integer] how many bytes to read from the IO
  # @return [String,nil] a String in binary encoding or nil
  def read(n)
  end
end

# Used as a stand-in for any IO-ish that responds to `#read`, `#seek`, `#pos` and `#size`
# This module is defined for YARD docs so that Sorbet has a proper type definition.
module RandomReadIO
  # @param n[Integer] how many bytes to read from the IO
  # @return [String,nil] a String in binary encoding or nil
  def read(n)
  end

  # @param to_absolute_offset[Integer] the absolute offset in the IO to seek to
  # @return [0]
  def seek(to_absolute_offset)
  end

  # @return [Integer] current position in the IO
  def pos
  end

  # @return [Integer] the total size of the data in the IO
  def size
  end
end

# Used as a stand-in for any IO that responds to `#write`
# This module is defined for YARD docs so that Sorbet has a proper type definition.
module WritableIO
  # @param string[String] the bytes to write into the IO
  # @return [Integer] the amount of bytes consumed. Will usually be `bytes.bytesize`
  def write(string)
  end
end
