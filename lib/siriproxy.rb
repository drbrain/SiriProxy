require 'eventmachine'
require 'zlib'
require 'pp'

class String
  def to_hex(seperator=" ")
    bytes.to_a.map{|i| i.to_s(16).rjust(2, '0')}.join(seperator)
  end
end

class SiriProxy
  def initialize config
    @log           = config.log
    @plugin_config = config.plugins
    @port          = config.port
    @upstream_dns  = config.upstream_dns
    @user          = config.user

    EventMachine.run do
      begin
        @log.info "Starting SiriProxy on port #{@port}.."

        EventMachine::start_server('0.0.0.0', @port, SiriProxy::Connection::Iphone, @log, @upstream_dns) { |conn|
          @log.info "start conn #{conn.inspect}"
          conn.plugin_manager = SiriProxy::PluginManager.new(@plugins)
          conn.plugin_manager.iphone_conn = conn
        }
      rescue RuntimeError => err
        if err.message == "no acceptor"
          raise "Cannot start the server on port #{@port} - are you root, or have another process on this port already?"
        else
          raise
        end
      end

      EventMachine.set_effective_user(@user) if @user
    end
  end
end
