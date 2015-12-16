require 'socket'
require 'http/parser'
require 'digest/sha1'
require 'base64'

require 'awesome_print'

#
# This class parses WebSocket messages and frames.
#
# Each message is divied in frames as described in RFC 6455.
#
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-------+-+-------------+-------------------------------+
#   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
#   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
#   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
#   | |1|2|3|       |K|             |                               |
#   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
#   |     Extended payload length continued, if payload len == 127  |
#   + - - - - - - - - - - - - - - - +-------------------------------+
#   |                               |Masking-key, if MASK set to 1  |
#   +-------------------------------+-------------------------------+
#   | Masking-key (continued)       |          Payload Data         |
#   +-------------------------------- - - - - - - - - - - - - - - - +
#   :                     Payload Data continued ...                :
#   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
#   |                     Payload Data continued ...                |
#   +---------------------------------------------------------------+
#
# for more info on the frame format see: http://tools.ietf.org/html/rfc6455#section-5
#
# fin:0 rsv:3 opcode:4 mask:1 payload_length:7/7+16/7+64 masking_key:0/4*8 payload_data:n*8

module Websock
  class Util
    PROTOCOL_VERSION = 13
    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    OPCODES = {
      0  => :continuation,
      1  => :text,
      2  => :binary,
      8  => :close,
      9  => :ping,
      10 => :pong
    }
    CRLF = "\r\n"

    class << self
      def accept_key(key)
        Base64.encode64(Digest::SHA1.digest(key + GUID)).strip
      end

      def fin(first_blood)
        first_blood[0].to_i
      end

      def opcode(first_blood)
        first_blood[4..7].to_i(16)
      end

      def valid_opcode?(first_blood)
        opcode = opcode(first_blood)
        # not support 3-7(reserved for further non-control frames) and 11-15(reserved for further control frames)
        OPCODES.keys.include?(opcode)
      end

      def mask(second_blook)
        second_blook[0].to_i
      end

      def payload_length(second_blook)
        second_blook[1..7].to_i(2)
      end

      def masking_key(raw_data)
        raw_data[2..5].unpack('C*')
      end

      def payload_data(raw_data, payload_length)
        data_size = raw_data.size
        raw_data[(data_size - payload_length)..(data_size - 1)]
      end

      def unmask(payload_data, masking_key)
        masked_data = ''.encode!('ASCII-8BIT')
        payload_data.bytes.each_with_index do |byte, i|
          masked_data << (byte ^ masking_key[i % 4])
        end
        masked_data
      end

      def make_res(payload)
        first_byte = 0b10000001
        second_byte = 0b00000000 # no mask
        second_byte |= payload.size
        res = ''
        res += first_byte.chr
        res += second_byte.chr
        res += payload
        res
      end
    end
  end
end

server = TCPServer.open(8080)
loop do
  Thread.start(server.accept) do |client|
    recv_length = 1024
    while tmp = client.recv(recv_length)
      data = ''
      data += tmp

      html_status_line_reg = /(.*)\s(.*)\sHTTP\/1\.(\d)\r\n.*/m

      if html_status_line_reg =~ data # http or websocket handshake
        parser = Http::Parser.new
        parser << data

        headers = parser.headers
        ap headers
        if headers['Sec-WebSocket-Version'] == '13' && !headers['Sec-WebSocket-Key'].nil? && (headers['Connection'] == 'keep-alive, Upgrade' || headers['Connection'] == 'Upgrade') && headers['Upgrade'] == 'websocket'
          p 'websocket handshake'
          sec_websocket_accept = Websock::Util.accept_key(headers['Sec-WebSocket-Key'])

          res = "HTTP/1.1 101 Switching Protocols#{Websock::Util::CRLF}Upgrade: websocket#{Websock::Util::CRLF}Connection: Upgrade#{Websock::Util::CRLF}Sec-WebSocket-Accept: #{sec_websocket_accept}#{Websock::Util::CRLF * 2}"

          client.write(res)
          client.flush
        else # not handle http
          client.write("bye bye#{Websock::Util::CRLF}")
          break
        end
      else
        p 'other protocol, maybe websocket'
        first_blood, second_blook = [data[0], data[1]].map { |d| d.unpack('C')[0].to_s(2) }
        fin = Websock::Util.fin(first_blood)
        opcode = Websock::Util.opcode(first_blood)
        p "opcode is #{Websock::Util::OPCODES[opcode]}"
        mask = Websock::Util.mask(second_blook)
        p "mask is #{mask}"
        payload_length = Websock::Util.payload_length(second_blook)
        p "payload_length is #{payload_length}"
        if fin == 1
          # FIXME: 只支持小于126字节的数据
          if payload_length < 126
            if mask == 1
              masking_key = Websock::Util.masking_key(data)
              payload_data = Websock::Util.payload_data(data, payload_length)

              # payload unmask
              unmasked_data = Websock::Util.unmask(payload_data, masking_key)
              p "unmasked_data is #{unmasked_data}"

              if masked_data == 'ping' # write pong
                client.write Websock::Util.make_res('pong')
                client.flush
              end
            else
              payload_data = data[(data.size - payload_length)..(data.size - 1)].unpack('C*').map(&:chr)
              p "payload_data is #{payload_data}"
            end
          end
        else
          # FIXME: 数据完整性
          p '继续接收数据'
        end
      end
    end
    client.close
  end
end
