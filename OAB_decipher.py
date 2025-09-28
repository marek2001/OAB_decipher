# oab_details_to_json.py
from struct import unpack
from io import BytesIO
import math
import binascii
import json
import re
from schema import PidTagSchema

# ----------------------- basic helpers -----------------------

def hexify(prop_id: int) -> str:
    """Return 8-hex-digit uppercase string without 0x prefix."""
    return f"{prop_id:#010x}".upper()[2:]

def read_c_string(chunk: BytesIO) -> str:
    """Read a NULL-terminated byte string; try UTF-8 then CP1252."""
    buf = bytearray()
    while True:
        b = chunk.read(1)
        if b in (b"", b"\x00"):
            break
        buf.extend(b)
    if not buf:
        return ""
    for enc in ("utf-8", "cp1252"):
        try:
            return buf.decode(enc)
        except UnicodeDecodeError:
            pass
    return buf.decode("utf-8", errors="replace")

def read_varint(chunk: BytesIO) -> int:
    """
    OAB variable-length integer:
      - First byte is a count.
      - If 0x81..0x84: next (count-0x80) bytes form a LE uint (pad to 4).
      - If <= 127: it's the value.
      - Else: return -1 (sentinel/unknown).
    """
    b = chunk.read(1)
    if b == b"":
        return -1
    byte_count = unpack("<B", b)[0]
    if 0x81 <= byte_count <= 0x84:
        n = byte_count - 0x80
        data = chunk.read(n)
        data = (data + b"\x00\x00\x00")[:4]
        return unpack("<I", data)[0]
    if byte_count > 127:
        return -1
    return byte_count

def hexlify_bytes(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

# ----------------------- email filtering -----------------------

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _strip_type_prefix(addr: str) -> str:
    """
    Remove leading type prefixes like 'SMTP:', 'smtp:', 'mailto:', 'X500:', 'EX:'.
    Returns the substring after the first colon, if any.
    """
    if not isinstance(addr, str):
        return ""
    if ":" in addr:
        _t, rest = addr.split(":", 1)
        return rest
    return addr

def _is_legacy_dn(s: str) -> bool:
    """
    Detect Exchange legacy DN / X.500 forms:
      '/o=Org/ou=Group/...'
      'X500:/o=...'
      'EX:/o=...'
    """
    if not s:
        return False
    u = s.strip()
    if u.startswith("/o=") or u.startswith("/O="):
        return True
    u_upper = u.upper()
    return u_upper.startswith("X500:/O=") or u_upper.startswith("EX:/O=")

def _is_smtp_addr(s: str) -> bool:
    """Minimal SMTP sanity check."""
    return bool(EMAIL_RE.match(s))

def collect_smtp_emails(rec: dict) -> list[str]:
    """
    Return de-duplicated SMTP addresses for a record, primary first if present.
    Looks at PrimarySmtpAddress, SmtpAddress, EmailAddress, Email,
    and multi-value fields like EmailAddresses/EmailAddressList.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add(addr: str):
        if not isinstance(addr, str):
            return
        addr = _strip_type_prefix(addr.strip())
        if not addr or _is_legacy_dn(addr) or not _is_smtp_addr(addr):
            return
        key = addr.lower()
        if key not in seen:
            seen.add(key)
            out.append(addr)

    # Prefer explicit primary first
    add(rec.get("PrimarySmtpAddress"))

    # Other single-value fields
    for k in ("SmtpAddress", "EmailAddress", "Email"):
        add(rec.get(k))

    # Multi-value fields often include typed values (SMTP:, X500:, EX:, SIP:, etc.)
    for k in ("EmailAddresses", "EmailAddressList", "AddressBookProxyAddresses"):
        vs = rec.get(k)
        if isinstance(vs, list):
            for v in vs:
                add(v)

    return out

# ----------------------- parser -----------------------

def parse_oab_details(path: str, max_records: int | None = None):
    """
    Parse an OAB v4 details file and return a dict with metadata and records.
    Cleans email-related fields and adds `Emails` array (SMTP only).
    """
    records: list[dict] = []
    name_to_number: dict[str, str] = {}

    with open(path, "rb") as f:
        ulVersion, ulSerial, ulTotRecs = unpack("<III", f.read(12))
        assert ulVersion == 32, "This only supports OAB Version 4 Details File"

        # OAB_META_DATA
        cbSize = unpack("<I", f.read(4))[0]
        meta = BytesIO(f.read(cbSize - 4))

        # Header attributes (ignored)
        hdr_count = unpack("<I", meta.read(4))[0]
        for _ in range(hdr_count):
            _ = meta.read(8)  # ulPropID + ulFlags

        # OAB attributes we will parse
        oab_count = unpack("<I", meta.read(4))[0]
        oab_atts: list[int] = []
        for _ in range(oab_count):
            ulPropID = unpack("<I", meta.read(4))[0]
            _ulFlags = unpack("<I", meta.read(4))[0]
            oab_atts.append(ulPropID)

        # Skip header record
        cbSize = unpack("<I", f.read(4))[0]
        _ = f.read(cbSize - 4)

        # Records
        count = 0
        while True:
            if max_records is not None and count >= max_records:
                break

            size_prefix = f.read(4)
            if size_prefix == b"":
                break  # EOF

            cbSize = unpack("<I", size_prefix)[0]
            chunk = BytesIO(f.read(cbSize - 4))

            # presence bit array (which props are present)
            presence_len = int(math.ceil(oab_count / 8.0))
            presence = bytearray(chunk.read(presence_len))
            indices = [i for i in range(oab_count)
                       if ((presence[i // 8] >> (7 - (i % 8))) & 1) == 1]

            rec: dict = {}

            for i in indices:
                prop_key = hexify(oab_atts[i])
                if prop_key not in PidTagSchema:
                    # Unknown property; safest is to skip (we don't know size/type).
                    continue
                name, ptype = PidTagSchema[prop_key]

                if ptype in ("PtypString8", "PtypString"):
                    rec[name] = read_c_string(chunk)

                elif ptype == "PtypBoolean":
                    rec[name] = bool(unpack("<?", chunk.read(1))[0])

                elif ptype == "PtypInteger32":
                    rec[name] = read_varint(chunk)

                elif ptype == "PtypBinary":
                    n = read_varint(chunk)
                    rec[name] = hexlify_bytes(chunk.read(max(n, 0)))

                elif ptype in ("PtypMultipleString", "PtypMultipleString8"):
                    n = read_varint(chunk)
                    rec[name] = [read_c_string(chunk) for _ in range(max(n, 0))]

                elif ptype == "PtypMultipleInteger32":
                    n = read_varint(chunk)
                    vals = []
                    for _ in range(max(n, 0)):
                        v = read_varint(chunk)
                        if name == "OfflineAddressBookTruncatedProperties":
                            hv = hexify(v)
                            v = PidTagSchema.get(hv, (hv, ""))[0]
                        vals.append(v)
                    rec[name] = vals

                elif ptype == "PtypMultipleBinary":
                    n = read_varint(chunk)
                    arr = []
                    for _ in range(max(n, 0)):
                        blen = read_varint(chunk)
                        arr.append(hexlify_bytes(chunk.read(max(blen, 0))))
                    rec[name] = arr

                else:
                    raise ValueError(f"Unknown property type: {ptype} for {name}")

            # -------- cleanup / normalization for email-related fields --------

            # 1) EmailAddress: move legacy DN to LegacyExchangeDN; keep SMTP only; otherwise drop
            if "EmailAddress" in rec and isinstance(rec["EmailAddress"], str):
                raw = rec["EmailAddress"].strip()
                stripped = _strip_type_prefix(raw)
                if _is_legacy_dn(stripped):
                    rec["LegacyExchangeDN"] = raw    # preserve original DN
                    rec.pop("EmailAddress", None)    # remove from EmailAddress
                elif _is_smtp_addr(stripped):
                    rec["EmailAddress"] = stripped   # keep as plain SMTP
                else:
                    rec.pop("EmailAddress", None)

            # 2) SmtpAddress: strip prefix, validate or drop
            if "SmtpAddress" in rec and isinstance(rec["SmtpAddress"], str):
                sm = _strip_type_prefix(rec["SmtpAddress"].strip())
                if _is_smtp_addr(sm):
                    rec["SmtpAddress"] = sm
                else:
                    rec.pop("SmtpAddress", None)

            # 3) AddressBookProxyAddresses: replace with SMTP-only list (plain addresses)
            if "AddressBookProxyAddresses" in rec and isinstance(rec["AddressBookProxyAddresses"], list):
                smtp_only: list[str] = []
                for a in rec["AddressBookProxyAddresses"]:
                    if not isinstance(a, str):
                        continue
                    stripped = _strip_type_prefix(a.strip())
                    if _is_legacy_dn(stripped):
                        continue
                    if _is_smtp_addr(stripped):
                        if stripped.lower() not in {x.lower() for x in smtp_only}:
                            smtp_only.append(stripped)
                rec["AddressBookProxyAddresses"] = smtp_only

            # 4) Add unified Emails list (SMTP only; primary first)
            rec["Emails"] = collect_smtp_emails(rec)

            # Optional: DisplayName -> trailing number in parentheses
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

# ----------------------- run (no CLI args) -----------------------

if __name__ == "__main__":
    in_path = "udetails.oab"
    result = parse_oab_details(in_path)

    with open("details.json", "w", encoding="utf-8") as out:
        json.dump(result, out, ensure_ascii=False, indent=2)

    print(
        f"Parsed {result['parsed_records']} records "
        f"(claimed total {result['reported_total_records']}). "
        f"Wrote details.json"
    )
