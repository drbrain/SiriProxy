require 'cfpropertylist'
require 'siriproxy/interpret_siri'

class SiriProxy::Connection < EventMachine::Connection
  include EventMachine::Protocols::LineText2

  attr_accessor :other_connection, :name, :ssled, :output_buffer, :input_buffer, :processed_headers, :unzip_stream, :zip_stream, :consumed_ace, :unzipped_input, :unzipped_output, :last_ref_id, :plugin_manager

  def last_ref_id=(ref_id)
    @last_ref_id = ref_id
    self.other_connection.last_ref_id = ref_id if other_connection.last_ref_id != ref_id
  end

  def initialize log
    super()
    @log = log
    self.processed_headers = false
    self.output_buffer = ""
    self.input_buffer = ""
    self.unzipped_input = ""
    self.unzipped_output = ""
    self.unzip_stream = Zlib::Inflate.new
    self.zip_stream = Zlib::Deflate.new
    self.consumed_ace = false
  end

  def post_init
    self.ssled = false
  end

  def ssl_handshake_completed
    self.ssled = true

    @log.info "#{self.name} SSL completed"
  end

  def receive_line(line) #Process header
    @log.info "#{self.name} header #{line}"
    if(line == "") #empty line indicates end of headers
      @log.debug "#{self.name} end of headers"
      set_binary_mode
      self.processed_headers = true
    end
    self.output_buffer << (line + "\x0d\x0a") #Restore the CR-LF to the end of the line

    flush_output_buffer()
  end

  def receive_binary_data(data)
    self.input_buffer << data

    ##Consume the "0xAACCEE02" data at the start of the stream if necessary (by forwarding it to the output buffer)
    if(self.consumed_ace == false)
      self.output_buffer << input_buffer[0..3]
      self.input_buffer = input_buffer[4..-1]
      self.consumed_ace = true;
    end

    process_compressed_data()

    flush_output_buffer()
  end

  def flush_output_buffer
    return if output_buffer.empty?

    if other_connection.ssled
      @log.debug "#{self.name} forwarding #{@output_buffer.length} bytes to #{other_connection}.name}"
      other_connection.send_data(output_buffer)
      self.output_buffer = ""
    else
      @log.debug "#{self.name} buffering #{@output_buffer.length} bytes"
    end
  end

  def process_compressed_data
    self.unzipped_input << unzip_stream.inflate(self.input_buffer)
    self.input_buffer = ""
    @log.debug "#{self.name} unzipped #{unzipped_input}"

    while(self.has_next_object?)
      object = read_next_object_from_unzipped()

      if(object != nil) #will be nil if the next object is a ping/pong
        new_object = prep_received_object(object) #give the world a chance to mess with folks

        inject_object_to_output_stream(new_object) if new_object != nil #might be nil if "the world" decides to rid us of the object
      end
    end
  end

  def has_next_object?
    return false if unzipped_input.empty? #empty
    unpacked = unzipped_input[0...5].unpack('H*').first
    return true if(unpacked.match(/^0[34]/)) #Ping or pong

    if unpacked.match(/^[0-9][15-9]/)
      puts "ROGUE PACKET!!! WHAT IS IT?! TELL US!!! IN IRC!! COPY THE STUFF FROM BELOW"
      puts unpacked.to_hex
    end
    objectLength = unpacked.match(/^0200(.{6})/)[1].to_i(16)
    return ((objectLength + 5) < unzipped_input.length) #determine if the length of the next object (plus its prefix) is less than the input buffer
  end

  def read_next_object_from_unzipped
    unpacked = unzipped_input[0...5].unpack('H*').first
    info = unpacked.match(/^0(.)(.{8})$/)

    if(info[1] == "3" || info[1] == "4") #Ping or pong -- just get these out of the way (and log them for good measure)
      object = unzipped_input[0...5]
      self.unzipped_output << object

      type = (info[1] == "3") ? "Ping" : "Pong"
      @log.info "#{self.name} #{self.type} #{info[2].to_i 16}"
      self.unzipped_input = unzipped_input[5..-1]

      flush_unzipped_output()
      return nil
    end

    object_size = info[2].to_i(16)
    prefix = unzipped_input[0...5]
    object_data = unzipped_input[5...object_size+5]
    self.unzipped_input = unzipped_input[object_size+5..-1]

    parse_object(object_data)
  end

  def parse_object(object_data)
    plist = CFPropertyList::List.new(:data => object_data)
    object = CFPropertyList.native_types(plist.value)

    object
  end

  def inject_object_to_output_stream(object)
    if object["refId"] != nil && !object["refId"].empty?
      @block_rest_of_session = false if @block_rest_of_session && self.last_ref_id != object["refId"] #new session
      self.last_ref_id = object["refId"]
    end

    @log.info "#{self.name} forwarding #{object['class']} to #{@other_connection.name}"

    object_data = object.to_plist(:plist_format => CFPropertyList::List::FORMAT_BINARY)

    #Recalculate the size in case the object gets modified. If new size is 0, then remove the object from the stream entirely
    obj_len = object_data.length

    if(obj_len > 0)
      prefix = [(0x0200000000 + obj_len).to_s(16).rjust(10, '0')].pack('H*')
      self.unzipped_output << prefix + object_data
    end

    flush_unzipped_output()
  end

  def flush_unzipped_output
    self.zip_stream << self.unzipped_output
    self.unzipped_output = ""
    self.output_buffer << zip_stream.flush

    flush_output_buffer()
  end

  def prep_received_object(object)
    if object["refId"] == self.last_ref_id && @block_rest_of_session
      @log.info "#{self.name} dropping #{object['class']}"
      return nil
    end

    @log.info "#{self.name} received #{object['class']}"
    @log.debug "#{self.name} group: #{object['group']} ref_id: #{object['refId']} ace_id: #{object['aceId']}"

    #keeping this for filters
    new_obj = received_object(object)
    if new_obj == nil
      @log.info "#{self.name} dropping #{object['class']}"
      return nil
    end

    #block the rest of the session if a plugin claims ownership
    speech = SiriProxy::Interpret.speech_recognized(object)
    if speech != nil
      inject_object_to_output_stream(object)
      block_rest_of_session if plugin_manager.process(speech)
      return nil
    end

    #object = new_obj if ((new_obj = SiriProxy::Interpret.unknown_intent(object, self, plugin_manager.method(:unknown_command))) != false)
    #object = new_obj if ((new_obj = SiriProxy::Interpret.speech_recognized(object, self, plugin_manager.method(:speech_recognized))) != false)

    object
  end

  #Stub -- override in subclass
  def received_object(object)
    object
  end

end
