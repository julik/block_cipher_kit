# Used as a stand-in for any IO-ish that responds to #read
module StraightReadableIO
  # @param [Integer] how many bytes to read from the IO
  # @return [String,nil] a String in binary encoding or nil
  def read(n)
  end
end

# Used as a stand-in for any IO-ish that responds to `#read`, `#seek`, `#pos` and `#size`
module RandomReadIO
  # @param [Integer] how many bytes to read from the IO
  # @return [String,nil] a String in binary encoding or nil
  def read(n)
  end

  # @param [Integer] the absolute offset in the IO to seek to
  # @return 0
  def seek(to_absolute_offset)
  end

  # @return [Integer] current position in the IO
  def pos
  end

  # @return [Integer] the total size of the data in the IO
  def size
  end
end

module WritableIO
  # @param [String] the bytes to write into the IO
  # @return [Integer] the amount of bytes consumed. Will usually be `bytes.bytesize`
  def write(n)
  end
end
