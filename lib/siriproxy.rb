require 'eventmachine'
require 'zlib'
require 'pp'

class String
  def to_hex(seperator=" ")
    bytes.to_a.map{|i| i.to_s(16).rjust(2, '0')}.join(seperator)
  end
end

class SiriProxy
  def initialize app_config
    @plugin_config = app_config.plugins
    @port          = app_config.port
    @upstream_dns  = app_config.upstream_dns
    @user          = app_config.user
    # @todo shouldnt need this, make centralize logging instead
    $LOG_LEVEL = @app_config.log_level.to_i

    EventMachine.run do
      begin
        puts "Starting SiriProxy on port #{@port}.."

        EventMachine::start_server('0.0.0.0', @port, SiriProxy::Connection::Iphone, @upstream_dns) { |conn|
          $stderr.puts "start conn #{conn.inspect}"
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
