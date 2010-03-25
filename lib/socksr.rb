#
# http://tools.ietf.org/html/rfc1928
#

require 'socket'
require 'logger'

$log = Logger.new(STDOUT)
$log.level = Logger::WARN

# Socks 5 protocol constant value
SOCKS5_VERSION 				      = 0x05

METHOD_NO_AUTHENTICATION 	  = 0x00
METHOD_GSSAPI 				      = 0x01
METHOD_USERNAME_PASSWORD	  = 0x02
METHOD_NO_ACCEPTABLE_METHOD = 0xFF

# The negotiation for the authentication method request data length
LEAST_METHOD_REQUEST_LENGTH = 3

COMMAND_CONNECT       			= 0x01
COMMAND_BIND      					= 0x02
COMMAND_UDP_ASSOCIATE   		= 0x03
COMMAND_LIST = [
  COMMAND_CONNECT,
  COMMAND_BIND,
  COMMAND_UDP_ASSOCIATE,
]

# Address type
ADDRESS_TYPE_IP_V4					= 0x01
ADDRESS_TYPE_DOMAIN_NAME		= 0x03
ADDRESS_TYPE_IP_V6					= 0x04
ADDRESS_TYPE_LIST = [
  ADDRESS_TYPE_IP_V4,
  ADDRESS_TYPE_DOMAIN_NAME,
  ADDRESS_TYPE_IP_V6,
]

# Sockets protocol constant values.
ERR_CONNECTION_RESET_BY_PEER    = 10054
ERR_CONNECTION_REFUSED          = 10061


BUFFER_SIZE = 1024

# Serve connected client
# 
# @param [Socket] io the connected cient socket
def serve(io)
	unless process_method_request(io)
    $log.info {"Disconnect client from #{io.peeraddr[2]}"}
		io.close
		exit
	end

	unless process_command_request(io)
		io.close
		exit
	end
end

def process_command_request(io)
  begin
    req = io.sysread(BUFFER_SIZE)
  rescue SystemCallError => e
    $log.error("Read client command request error => #{e}")
    return false
  rescue EOFError => e
    $log.error("Client on #{io.peeraddr[2]} close connection")
    return false
  end

  # Socks version
  socks_version = req[0]
  if socks_version != SOCKS5_VERSION
    $log.error {"Request_Bad_Version => #{SOCKS5_VERSION} expected, actual is #{socks_version}"}
    return false
  end

  # Connection Type
  cmd = req[1]
  $log.debug {"cmd => #{cmd}"}
  # Reserved byte, must be 0x00
  rsv = req[2]
  $log.debug {"rsv => #{rsv}"}

  if rsv != 0x00
    $log.error {"Client command request invalid format, rsv byte is not zero"}
    begin
      io.syswrite([SOCKS5_VERSION, 0xff].pack("C*"))
    rescue SystemCallError => e
      $log.error {"Write command response error => #{e}"}
    end
    return false
  end

  raw_host = nil
  host = nil
  raw_port = nil
  port = nil

  # get host and port
  atyp = req[3]
  case atyp
  when ADDRESS_TYPE_IP_V4
    # get host
    $log.debug {"Address type is ip v4"}
    # ip v4, 4 bytes
    raw_host = req[4, 4].unpack("C*")
    host = raw_host.join(".")
    $log.debug {"raw_host => #{raw_host}"}
    $log.debug {"host => #{host}"}

    # check host valid
    unless host && host.length > 0
      $log.error {"Host not valid"}
      return false
    end

    # get port
    raw_port = req[8, 2].unpack("C*")
    port = raw_port[0] << 8 | raw_port[1]

  when ADDRESS_TYPE_DOMAIN_NAME
    # get host
    $log.debug {"Address type is domain name"}
    # domain name, variable length, the first byte of DST.ADDR section indicate the domain name length
    domain_length = req[4]
    if domain_length < 1
      $log.error {"Domain length not valid => #{domain_length}"}
      return false
    end
    
    host = req[5, domain_length]
    raw_host = host.unpack("C*")
    $log.debug {"raw_host => #{raw_host}"}
    $log.debug {"host => #{host}"}

    # get port
    raw_port = req[5 + domain_length, 2].unpack("C*")
    port = raw_port[0] << 8 | raw_port[1]

  when ADDRESS_TYPE_IP_V6
    $log.debug {"Address type is ip v6"}
    # ip v6
    $log.error {"IP V6 not implemented"}
    return false
  end

  $log.debug {"raw_port => #{raw_port}"}
  $log.debug {"port => #{port}"}
    
  # check port valid
  unless port && port >= 0 && port <= 65535
    $log.error {"Port not valid"}
    return false
  end
  
  # forward data
  socks_do(cmd, io, host, port, atyp, raw_host, raw_port)
end

def socks_do(cmd, client, host, port, atyp, raw_host, raw_port)
  client_addr = client.peeraddr[2]
  target_addr = ''
  cli_buf = ''
  srv_buf = ''

  $log.debug {"cmd => #{cmd}, host => #{host}, port => #{port}"}

  case cmd
  when COMMAND_CONNECT # Just to tcp forward
	  $log.debug {"Client #{client_addr} connecting to #{host}:#{port} ..."}
    target = TCPSocket.open(host, port)
    if target
      target_addr = target.peeraddr[2]
	    $log.debug {"Client #{client_addr} connecting to #{host}:#{port} successed"}
      # syswrite to client
      resp = [SOCKS5_VERSION, 0x00, 0x00].push(atyp).concat(raw_host).concat(raw_port)
      $log.debug {"syswrite resp => #{resp.inspect}"}
      begin
        client.syswrite(resp.pack("C*"))
      rescue SystemCallError => e
        $log.error {"Write command response to client #{client_addr} error => #{e}"}
        target.close
        return false
      end
      loop do # main loop
        readables, writeables, exceptions = IO.select([client, target])
        if exceptions
          $log.error {"Error in select"}
          return false
        end
        
        readables.each do |io|
          if io == client
            $log.debug {"client can sysread"}
            begin
              cli_buf = client.sysread(BUFFER_SIZE)
            rescue SystemCallError => e
              $log.error {"Read client #{client_addr} error => #{e}"}
              target.close
              return false
            rescue EOFError => e
              $log.error {"Client #{client_addr} close connection"}
              target.close
              return false
            end
            $log.debug {"sysread from client => #{cli_buf.length} bytes"}

            begin
              target.syswrite(cli_buf)
            rescue SystemCallError => e
              $log.error {"Write target #{target_addr} error => #{e}"}
              target.close
              return false
            end
          elsif io == target
            $log.debug {"target can sysread"}
            begin
              srv_buf = target.sysread(BUFFER_SIZE)
            rescue SystemCallError => e
              $log.error {"Read target #{target_addr} error => #{e}"}
              target.close
              return false
            rescue EOFError => e
              $log.error {"Target #{target_addr} close connection"}
              target.close
              return false
            end
            $log.debug {"sysread from target => #{srv_buf.length} bytes"}

            begin
              client.syswrite(srv_buf)
            rescue SystemCallError => e
              $log.error {"Write client #{client_addr} error => #{e}"}
              target.close
              return false
            end
          end
        end
      end
    else
      $log.error {"connecting to #{host}:#{port} fail"}
      resp = [0x05, 0x01, 0x00].push(atyp).concat(raw_host).concat(raw_port)
      $log.debug {"syswrite resp => #{resp.inspect}"}
      begin
        client.syswrite(resp.pack("C*"))
      rescue SystemCallError
        $log.error {"Write client #{client_addr} error => #{e}"}
      end
      return false
    end
  when COMMAND_BIND
    # BIND X'02'
    $log.error {"Command Bind not implemented yet"}
    return false
  when COMMAND_UDP_ASSOCIATE
    # UDP ASSOCIATE X'03'
    $log.error {"Command UDP ASSOCIDATE not implemented yet"}
    return false
  else
    # invalid command type
    $log.error {"Invalid Command type"}
    return false
  end
end

# Process negotiation for the authentication method to be used
# 
# @param [Socket] io the client socket
# @return [Boolean] status true for ok, false for fail
def process_method_request(io)
  begin
    req = io.sysread(BUFFER_SIZE)
  rescue SystemCallError => e
    $log.error("Read client authentication method select request error => #{e}")
    return false
  rescue EOFError => e
    $log.error("Client on #{io.peeraddr[2]} close connection")
    return false
  end

  if req.length < LEAST_METHOD_REQUEST_LENGTH
    $log.error {"Request_Invalid_Format => request length must be at least #{LEAST_METHOD_REQUEST_LENGTH}, actual is #{req.length}"}
    return false
  end

  # Socks version
  socks_version = req[0]
  if socks_version != SOCKS5_VERSION
    $log.error {"Request_Bad_Version => #{SOCKS5_VERSION} expected, actual is #{socks_version}"}
    return false
  end

  # number of authentication methods, at least one
  nmethods = req[1]
  if nmethods < 1
    $log.error {"Authentication methods must greater than zero => acutal is #{nmethods}"}
    return false
  end

  success = false
  nmethods.times do |i|
    if (method = req[2 + i]) == METHOD_NO_AUTHENTICATION # Only support anonymouse access
      begin
        io.syswrite([SOCKS5_VERSION, METHOD_NO_AUTHENTICATION].pack("C*"))
      rescue SystemCallError => e
        $log.error {"Write to client authentication method select response error => #{e}"}
        return false
      end
      success = true
      $log.debug("Socks server selected authentication method is => #{method}")
      break
    end
  end
  return success
end

server = TCPServer.new(1080)

$log.info {"Ruby Socks5 Server running on #{Socket.gethostname}"}

trap("INT") { server.stop }

while client = server.accept do
  $log.info {"Accepted connection from #{client.peeraddr[2]}"}
  pid = fork
  if pid.nil?
    # in child process
    serve(client)
  else
    # in parent process
    Process.detach(pid)
  end
end