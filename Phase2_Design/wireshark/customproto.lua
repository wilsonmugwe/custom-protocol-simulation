-- customproto.lua — Wireshark Lua dissector (with flags + UDP heuristic)

-- Header (network byte order):
--   0: version   (1 byte)   expect 0x01
--   1: msg_type  (1 byte)   {0x01=HELLO, 0x02=DATA, 0x03=ACK, 0x04=ERROR}
--   2..3: seq    (2 bytes, uint16)
--   4: flags     (1 byte)   F7..F0 bits
--   5..6: length (2 bytes, uint16)
--   7..         : data      (length bytes)

local DEFAULT_PORT = 5555

local MSG = {
  [0x01] = "HELLO",
  [0x02] = "DATA",
  [0x03] = "ACK",
  [0x04] = "ERROR",
}

local p = Proto("customproto", "Custom Protocol")

-- fields
local f_version = ProtoField.uint8 ("customproto.version",   "Version",  base.DEC)
local f_msgtype = ProtoField.uint8 ("customproto.msg_type", "Msg Type", base.HEX, {
  [0x01]="HELLO", [0x02]="DATA", [0x03]="ACK", [0x04]="ERROR"
})
local f_seq     = ProtoField.uint16("customproto.seq",      "Seq",      base.DEC)
local f_flags   = ProtoField.uint8 ("customproto.flags",    "Flags",    base.HEX)
-- individual flag bits (bitmask on the same byte)
local f_f7 = ProtoField.bool("customproto.flags.f7","F7", base.NONE, nil, 0x80)
local f_f6 = ProtoField.bool("customproto.flags.f6","F6", base.NONE, nil, 0x40)
local f_f5 = ProtoField.bool("customproto.flags.f5","F5", base.NONE, nil, 0x20)
local f_f4 = ProtoField.bool("customproto.flags.f4","F4", base.NONE, nil, 0x10)
local f_f3 = ProtoField.bool("customproto.flags.f3","F3", base.NONE, nil, 0x08)
local f_f2 = ProtoField.bool("customproto.flags.f2","F2", base.NONE, nil, 0x04)
local f_f1 = ProtoField.bool("customproto.flags.f1","F1", base.NONE, nil, 0x02)
local f_f0 = ProtoField.bool("customproto.flags.f0","F0", base.NONE, nil, 0x01)

local f_len     = ProtoField.uint16("customproto.length",   "Length",   base.DEC)
local f_data    = ProtoField.bytes ("customproto.data",     "Data")

p.fields = {
  f_version, f_msgtype, f_seq, f_flags, f_f7, f_f6, f_f5, f_f4, f_f3, f_f2, f_f1, f_f0,
  f_len, f_data
}

-- core dissector (assumes it's our protocol)
function p.dissector(buf, pinfo, root)
  local blen = buf:len()
  if blen < 7 then return end

  pinfo.cols.protocol = "CUST"

  local subtree = root:add(p, buf(0))
  subtree:add(f_version, buf(0,1))
  local m = buf(1,1):uint()
  subtree:add(f_msgtype, buf(1,1))
  subtree:add(f_seq,     buf(2,2))
  local flags_node = subtree:add(f_flags, buf(4,1))
  -- add bitfields as children
  flags_node:add(f_f7, buf(4,1))
  flags_node:add(f_f6, buf(4,1))
  flags_node:add(f_f5, buf(4,1))
  flags_node:add(f_f4, buf(4,1))
  flags_node:add(f_f3, buf(4,1))
  flags_node:add(f_f2, buf(4,1))
  flags_node:add(f_f1, buf(4,1))
  flags_node:add(f_f0, buf(4,1))

  local L = buf(5,2):uint()
  local len_field = subtree:add(f_len, buf(5,2))

  local payload_off = 7
  local remaining   = math.max(0, blen - payload_off)
  local payload_len = math.min(L, remaining)
  subtree:add(f_data, buf(payload_off, payload_len))

  if L > remaining then
    len_field:append_text(string.format("  (warning: %d > available %d)", L, remaining))
  end

  local seq = buf(2,2):uint()
  pinfo.cols.info = string.format("%s seq=%d len=%d",
    MSG[m] or string.format("0x%02X", m), seq, L)
end

-- simple heuristic: looks like our header?
local function heur_dissect_customproto(tvb, pinfo, tree)
  -- need at least header
  if tvb:len() < 7 then return false end

  local version = tvb(0,1):uint()
  local mtype   = tvb(1,1):uint()
  local L       = tvb(5,2):uint()

  -- sanity checks:
  -- version == 1, msg_type in known set, and length fits (or at least not absurd)
  if version ~= 0x01 then return false end
  if MSG[mtype] == nil then return false end
  if L > 65535 then return false end

  -- optional: soft length check (don't fail if truncated frames)
  local payload_off = 7
  if L > 0 and (payload_off + L) > tvb:len() + 4 then
    -- allow a little slop for fragmentation; adjust or remove as needed
    return false
  end

  -- looks like ours — dissect
  p.dissector(tvb, pinfo, tree)
  return true
end

-- register: fixed port + UDP heuristic
local udp_table = DissectorTable.get("udp.port")
udp_table:add(DEFAULT_PORT, p)
p:register_heuristic("udp", heur_dissect_customproto)
