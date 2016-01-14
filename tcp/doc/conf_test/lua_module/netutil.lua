
local netutil = {}

netutil.LITTLE_ENDIAN = true
--- Convert given short value to network byte order on little endian hosts
-- @param x Unsigned integer value between 0x0000 and 0xFFFF
-- @return  Byte-swapped value
-- @see     htonl
-- @see     ntohs
netutil.htons = function(x)
    if LITTLE_ENDIAN then
        return bit.bor(
            bit.rshift( x, 8 ),
            bit.band( bit.lshift( x, 8 ), 0xFF00 )
        )
    else
        return x
    end
end

--- Convert given long value to network byte order on little endian hosts
-- @param x Unsigned integer value between 0x00000000 and 0xFFFFFFFF
-- @return  Byte-swapped value
-- @see     htons
-- @see     ntohl
netutil.htonl = function(x)
    if LITTLE_ENDIAN then
        return bit.bor(
            bit.lshift( htons( bit.band( x, 0xFFFF ) ), 16 ),
            htons( bit.rshift( x, 16 ) )
        )
    else
        return x
    end
end

netutil.ntohs = netutil.htons
netutil.ntohl = netutil.htonl

netutil.packint16 = function(x)
	local ret
	local l = bit.rshift( x,8)
	local h = bit.band( x,0xff)
	if(  0 == l ) then 
		ret = "\0"
	else
		ret = string.format("%c", l )
	end
	if(  0 == h ) then 
		ret = ret .. "\0"
	else
		ret = ret .. string.format("%c", h)
	end
	return ret
end

netutil.unpackint16 = function(x)
	local h = tonumber(string.byte(x, 1, 1));
	local l = tonumber(string.byte(x, 2, 2));
	return h*256+l
end

netutil.packint32 = function(x)
	return netutil.packint16(bit.rshift( x,16)) .. netutil.packint16(bit.band(x,0xffff)) 
end

netutil.unpackint32 = function(x)	
	return 65536 * netutil.unpackint16( string.sub(x, 1, 2) ) + netutil.unpackint16( string.sub(x, 3, 4) )
end

return netutil

