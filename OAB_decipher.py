from struct import unpack
from io import BytesIO
import math
import binascii
from schema import PidTagSchema
import json
import re
import sys

# ---- helpers ---------------------------------------------------------------

def hexify(prop_id: int) -> str:
    # 0x0000ABCD as uppercase without 0x prefix, 8 hex digits
    return f"{prop_id:#010x}".upper()[2:]

def lookup(ulPropID: int) -> str:
    key = hexify(ulPropID)
    return PidTagSchema.get(key, (hex(ulPropID), ""))[0]

def read_c_string(chunk: BytesIO) -> str:
    """Read a NULL-terminated byte string and try UTF-8 first, then cp1252."""
    buf = bytearray()
    while True:
        b = chunk.read(1)
        if b == b"" or b == b"\x00":
            break
        buf.extend(b)
    if not buf:
        return ""
    # Try utf-8, then fall back (older OABs sometimes have CP1252 for *String8)
    for enc in ("utf-8", "cp1252"):
        try:
            return buf.decode(enc)
        except UnicodeDecodeError:
            continue
    # Last resort: replace errors
    return buf.decode("utf-8", errors="replace")

def read_varint(chunk: BytesIO) -> int:
    """
    OAB integer length encoding:
      - first byte is a count
      - if 0x81..0x84, the next (count-0x80) bytes form a little-endian int
      - if <= 127, it's the value itself
      - other high-bit values are often sentinels; return -1
    """
    b = chunk.read(1)
    if b == b"":
        return -1
    byte_count = unpack('<B', b)[0]
    if 0x81 <= byte_count <= 0x84:
        # read N bytes, pad to 4, little-endian
        n = byte_count - 0x80
        data = chunk.read(n)
        data = (data + b"\x00\x00\x00")[:4]
        return unpack('<I', data)[0]
    else:
        if byte_count > 127:
            return -1
        return byte_count

def hexlify_bytes(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

# ---- main -----------------------------------------------------------------

def parse_oab_details(path: str, max_records: int = None):
    records = []
    name_to_number = {}

    with open(path, "rb") as f:
        ulVersion, ulSerial, ulTotRecs = unpack("<III", f.read(12))
        assert ulVersion == 32, "This only supports OAB Version 4 Details File"

        # OAB_META_DATA
        cbSize = unpack("<I", f.read(4))[0]
        meta = BytesIO(f.read(cbSize - 4))

        # Header atts (ignored)
        HDR_cAtts = unpack("<I", meta.read(4))[0]
        for _ in range(HDR_cAtts):
            _ulPropID = unpack("<I", meta.read(4))[0]
            _ulFlags  = unpack("<I", meta.read(4))[0]

        # OAB attributes we care about
        OAB_cAtts = unpack("<I", meta.read(4))[0]
        OAB_Atts = []
        for _ in range(OAB_cAtts):
            ulPropID = unpack("<I", meta.read(4))[0]
            _ulFlags = unpack("<I", meta.read(4))[0]
            OAB_Atts.append(ulPropID)

        # Header record (skip)
        cbSize = unpack("<I", f.read(4))[0]
        _ = f.read(cbSize - 4)

        # Iterate records until EOF or max_records
        count = 0
        while True:
            if max_records is not None and count >= max_records:
                break

            size_prefix = f.read(4)
            if size_prefix == b"":
                break  # EOF

            cbSize = unpack("<I", size_prefix)[0]
            chunk = BytesIO(f.read(cbSize - 4))

            # presence bit array
            presence_len = int(math.ceil(OAB_cAtts / 8.0))
            presence = bytearray(chunk.read(presence_len))
            indices = [
                i for i in range(OAB_cAtts)
                if ((presence[i // 8] >> (7 - (i % 8))) & 1) == 1
            ]

            rec = {}
            for i in indices:
                prop_key = hexify(OAB_Atts[i])
                if prop_key not in PidTagSchema:
                    # Unknown property; skip gracefully
                    _ = read_varint(chunk)  # best effort skip for sized types
                    continue

                name, ptype = PidTagSchema[prop_key]

                if ptype in ("PtypString8", "PtypString"):
                    val = read_c_string(chunk)
                    rec[name] = val

                elif ptype == "PtypBoolean":
                    val = unpack("<?", chunk.read(1))[0]
                    rec[name] = bool(val)

                elif ptype == "PtypInteger32":
                    rec[name] = read_varint(chunk)

                elif ptype == "PtypBinary":
                    n = read_varint(chunk)
                    b = chunk.read(max(n, 0))
                    rec[name] = hexlify_bytes(b)

                elif ptype in ("PtypMultipleString", "PtypMultipleString8"):
                    count_strings = read_varint(chunk)
                    arr = [read_c_string(chunk) for _ in range(max(count_strings, 0))]
                    rec[name] = arr

                elif ptype == "PtypMultipleInteger32":
                    n = read_varint(chunk)
                    arr = []
                    for _ in range(max(n, 0)):
                        v = read_varint(chunk)
                        if name == "OfflineAddressBookTruncatedProperties":
                            hv = hexify(v)
                            if hv in PidTagSchema:
                                v = PidTagSchema[hv][0]
                            else:
                                v = hv
                        arr.append(v)
                    rec[name] = arr

                elif ptype == "PtypMultipleBinary":
                    n = read_varint(chunk)
                    arr = []
                    for _ in range(max(n, 0)):
                        blen = read_varint(chunk)
                        b = chunk.read(max(blen, 0))
                        arr.append(hexlify_bytes(b))
                    rec[name] = arr

                else:
                    # Unknown type: bail clearly rather than crash later
                    raise ValueError(f"Unknown property type: {ptype} for {name}")

            # Optional side-extract: DisplayName -> trailing number in parentheses
            dn = rec.get("DisplayName")
            if isinstance(dn, str):
                m = re.match(r"^([A-Za-z ]+) \(([0-9]+)\)$", dn)
                if m:
                    name_to_number[m.group(1)] = m.group(2)

            records.append(rec)
            count += 1

    return {
        "version": 4,
        "serial": ulSerial,
        "reported_total_records": ulTotRecs,
        "parsed_records": len(records),
        "records": records,
        "displayname_numbers": name_to_number
    }

if __name__ == "__main__":
    # Usage: python script.py udetails.oab [max_records]
    in_path = sys.argv[1] if len(sys.argv) > 1 else "udetails.oab"
    maxrecs = int(sys.argv[2]) if len(sys.argv) > 2 else None

    result = parse_oab_details(in_path, max_records=maxrecs)

    # Full JSON dump
    with open("details.json", "w", encoding="utf-8") as out:
        json.dump(result, out, ensure_ascii=False, indent=2)


    print(
        f"Parsed {result['parsed_records']} records "
        f"(claimed total {result['reported_total_records']})."
    )
