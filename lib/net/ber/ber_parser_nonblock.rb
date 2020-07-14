# Implements nonbocking and timeout handling routines for BER parsing.
module Net::BER::BERParserNonblock
  # Internal: Returns the BER message ID or nil.
  def read_ber_id
    ber_timeout_getbyte
  end
  private :read_ber_id

  # Internal: specify the BER socket read timeouts, nil by default (no timeout).
  attr_accessor :ber_io_deadline
  private :ber_io_deadline

  ##
  # sets a timeout of timeout seconds for read_ber and ber_timeout_write operations in the provided block the proin the future for if there is not already a earlier deadline set
  def with_timeout(timeout)
    timeout = timeout.to_f
    # don't change deadline if run without timeout
    return yield if timeout <= 0
    # clear deadline if it is not in the future
    self.ber_io_deadline = nil unless ber_io_timeout.to_f > 0
    new_deadline = Time.now + timeout
    # don't add deadline if current deadline is shorter
    return yield if ber_io_deadline && ber_io_deadline < new_deadline
    old_deadline = ber_io_deadline
    begin
      self.ber_io_deadline = new_deadline
      yield
    ensure
      self.ber_io_deadline = old_deadline
    end
  end

  # seconds until ber_io_deadline
  def ber_io_timeout
    ber_io_deadline ? ber_io_deadline - Time.now : nil
  end
  private :ber_io_timeout

  def read_select!
    return if IO.select([self], nil, nil, ber_io_timeout)
    raise Errno::ETIMEDOUT, "Timed out reading from the socket"
  end
  private :read_select!

  def write_select!
    return if IO.select(nil, [self], nil, ber_io_timeout)
    raise Errno::ETIMEDOUT, "Timed out reading from the socket"
  end
  private :write_select!

  # Internal: Replaces `getbyte` with nonblocking implementation.
  def ber_timeout_getbyte
    read_nonblock(1).ord
  rescue IO::WaitReadable
    read_select!
    retry
  rescue IO::WaitWritable
    write_select!
    retry
  rescue EOFError
    # nothing to read on the socket (StringIO)
    nil
  end
  private :ber_timeout_getbyte

  # Internal: Read `len` bytes, respecting timeout.
  def ber_timeout_read(len)
    buffer ||= ''.force_encoding(Encoding::ASCII_8BIT)
    begin
      read_nonblock(len, buffer)
      return buffer if buffer.bytesize >= len
    rescue IO::WaitReadable, IO::WaitWritable
      buffer.clear
    rescue EOFError
      # nothing to read on the socket (StringIO)
      nil
    end
    block ||= ''.force_encoding(Encoding::ASCII_8BIT)
    len -= buffer.bytesize
    loop do
      begin
        read_nonblock(len, block)
      rescue IO::WaitReadable
        read_select!
        retry
      rescue IO::WaitWritable
        write_select!
        retry
      rescue EOFError
        return buffer.empty? ? nil : buffer
      end
      buffer << block
      len -= block.bytesize
      return buffer if len <= 0
    end
  end
  private :ber_timeout_read

  ##
  # Writes val as a plain write would, but respecting the dealine set by with_timeout
  def ber_timeout_write(val)
    total_written = 0
    while val.bytesize > 0
      begin
        written = write_nonblock(val)
      rescue IO::WaitReadable
        read_select!
        retry
      rescue IO::WaitWritable
        write_select!
        retry
      end
      total_written += written
      val = val.byteslice(written..-1)
    end
    total_written
  end
end
