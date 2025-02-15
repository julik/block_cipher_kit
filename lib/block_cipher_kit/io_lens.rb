# frozen_string_literal: true

# Allows you to pass through the writes of a particular byte range only, discarding the rest
class BlockCipherKit::IOLens
  def initialize(io, range)
    @io = io
    @range = range
    @pos = 0
  end

  def write(bytes)
    previous_pos, @pos = @pos, @pos + bytes.bytesize
    return 0 if bytes.bytesize == 0

    location_in_output = Range.new(previous_pos, previous_pos + bytes.bytesize - 1)
    overlap = intersection_of(@range, location_in_output)
    if overlap
      at = overlap.begin - previous_pos
      n = overlap.end - overlap.begin + 1
      @io.write(bytes.byteslice(at, n))
    end

    bytes.bytesize
  end

  private

  # lifted from https://github.com/julik/range_utils/blob/master/lib/range_utils.rb
  def intersection_of(range_a, range_b)
    range_a = Range.new(range_a.begin, range_a.end.pred) if range_a.exclude_end?
    range_b = Range.new(range_b.begin, range_b.end.pred) if range_b.exclude_end?

    range_a = Range.new(0, range_a.end) if range_a.begin.nil?
    range_b = Range.new(0, range_b.end) if range_b.begin.nil?

    range_a = Range.new(range_a.begin, range_b.end) if range_a.end.nil?
    range_b = Range.new(range_b.begin, range_a.end) if range_b.end.nil?

    range_a, range_b = [range_a, range_b].sort_by(&:begin)
    return if range_a.end < range_b.begin

    heads_and_tails = [range_a.begin, range_b.begin, range_a.end, range_b.end].sort
    middle = heads_and_tails[1..-2]
    middle[0]..middle[1]
  end
end
