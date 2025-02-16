class BlockCipherKit::ReadWindowIO
  def initialize(io, starting_at_offset, window_size)
    @io = io
    @starting_at_offset = starting_at_offset.to_i
    @window_size = window_size.to_i
    @pos = 0
  end

  def size
    @window_size
  end

  attr_reader :pos

  def read(n_bytes)
    return "" if n_bytes == 0 # As hardcoded for all Ruby IO objects
    raise ArgumentError, "negative length #{n_bytes} given" if n_bytes < 0 # also as per Ruby IO objects

    window_limit = @starting_at_offset + @window_size
    wants_upto = @starting_at_offset + @pos + n_bytes

    read_limit = [window_limit, wants_upto].compact.min
    actual_n = read_limit - (@starting_at_offset + @pos)
    return if actual_n <= 0

    @io.seek(@starting_at_offset + @pos)
    @io.read(actual_n).tap { @pos += actual_n }
  end

  def seek(to_offset_in_window)
    raise ArgumentError, "negative seek destination #{to_offset_in_window}" if to_offset_in_window < 0 # also as per Ruby IO objects
    @pos = to_offset_in_window
    0
  end
end
