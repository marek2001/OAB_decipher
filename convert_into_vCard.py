# oab_to_vcard.py
from struct import unpack
from io import BytesIO
import math
import binascii
from schema import PidTagSchema
import sys
import re

# ---------- parsing helpers ----------
def hexify(prop_id: int) -> str:
    return f"{prop_id:#010x}".upper()[2:]

def read_c_string(chunk: BytesIO) -> str:
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

def parse_oab_details(path: str, max_records: int = None):
    records = []
    with open(path, "rb") as f:
        ulVersion, ulSerial, ulTotRecs = unpack("<III", f.read(12))
        assert ulVersion == 32, "This only supports OAB Version 4 Details File"

        cbSize = unpack("<I", f.read(4))[0]
        meta = BytesIO(f.read(cbSize - 4))

        HDR_cAtts = unpack("<I", meta.read(4))[0]
        for _ in range(HDR_cAtts):
            _ = meta.read(8)  # ulPropID + ulFlags

        OAB_cAtts = unpack("<I", meta.read(4))[0]
        OAB_Atts = []
        for _ in range(OAB_cAtts):
            ulPropID = unpack("<I", meta.read(4))[0]
            _ulFlags = unpack("<I", meta.read(4))[0]
            OAB_Atts.append(ulPropID)

        # skip header record
        cbSize = unpack("<I", f.read(4))[0]
        f.read(cbSize - 4)

        count = 0
        while True:
            if max_records is not None and count >= max_records:
                break
            size_prefix = f.read(4)
            if size_prefix == b"":
                break
            cbSize = unpack("<I", size_prefix)[0]
            chunk = BytesIO(f.read(cbSize - 4))

            presence_len = int(math.ceil(OAB_cAtts / 8.0))
            presence = bytearray(chunk.read(presence_len))
            indices = [i for i in range(OAB_cAtts)
                       if ((presence[i // 8] >> (7 - (i % 8))) & 1) == 1]

            rec = {}
            for i in indices:
                key = hexify(OAB_Atts[i])
                if key not in PidTagSchema:
                    continue
                name, ptype = PidTagSchema[key]

                if ptype in ("PtypString8", "PtypString"):
                    rec[name] = read_c_string(chunk)
                elif ptype == "PtypBoolean":
                    rec[name] = bool(unpack("<?", chunk.read(1))[0])
                elif ptype == "PtypInteger32":
                    rec[name] = read_varint(chunk)
                elif ptype == "PtypBinary":
                    n = read_varint(chunk)
                    rec[name] = binascii.hexlify(chunk.read(max(n, 0))).decode("ascii")
                elif ptype in ("PtypMultipleString", "PtypMultipleString8"):
                    n = read_varint(chunk)
                    rec[name] = [read_c_string(chunk) for _ in range(max(n, 0))]
                elif ptype == "PtypMultipleInteger32":
                    n = read_varint(chunk)
                    rec[name] = [read_varint(chunk) for _ in range(max(n, 0))]
                elif ptype == "PtypMultipleBinary":
                    n = read_varint(chunk)
                    arr = []
                    for _ in range(max(n, 0)):
                        blen = read_varint(chunk)
                        arr.append(binascii.hexlify(chunk.read(max(blen, 0))).decode("ascii"))
                    rec[name] = arr
            records.append(rec)
            count += 1
    return records

# ---------- vCard helpers ----------
def v_escape(s: str) -> str:
    if s is None:
        return ""
    return (s.replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace(",", "\\,")
            .replace(";", "\\;"))

def fold_line(line: str) -> str:
    limit = 75
    out = []
    while len(line) > limit:
        out.append(line[:limit])
        line = " " + line[limit:]
    out.append(line)
    return "\r\n".join(out)

def add_if(lines, prop, value, params=None):
    if not value:
        return
    p = ";" + ";".join(params) if params else ""
    lines.append(fold_line(f"{prop}{p}:{v_escape(value)}"))

def build_name_components(rec):
    given = rec.get("GivenName") or rec.get("FirstName") or ""
    family = rec.get("Surname") or rec.get("LastName") or ""
    middle = rec.get("MiddleName") or ""
    prefix = rec.get("DisplayNamePrefix") or rec.get("Prefix") or ""
    suffix = rec.get("Generation") or rec.get("Suffix") or ""
    return family, given, middle, prefix, suffix

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _strip_type_prefix(addr: str) -> str:
    """
    Exchange often stores addresses like:
      - 'SMTP:primary@domain'
      - 'smtp:alias@domain'
      - 'X500:/o=...'
      - 'EX:/o=...'
    Return the part after the first colon if present.
    """
    if ":" in addr:
        t, rest = addr.split(":", 1)
        # keep case-insensitive handling
        if t.lower() in ("smtp", "mailto", "x500", "ex"):
            return rest
    return addr

def _is_legacy_dn(s: str) -> bool:
    """
    Detect legacyExchangeDN / X.500 forms:
      '/o=Org/ou=Group/...'
      'X500:/o=...'
      'EX:/o=...'
    """
    if not s:
        return False
    u = s.strip()
    if u.startswith("/o="):
        return True
    # type-prefixed forms
    u_upper = u.upper()
    return u_upper.startswith("X500:/O=") or u_upper.startswith("EX:/O=")

def _is_smtp_addr(s: str) -> bool:
    """Minimal sanity check for SMTP addresses."""
    return bool(EMAIL_RE.match(s))

def collect_emails(rec):
    """
    Returns only SMTP addresses:
    - Prefer PrimarySmtpAddress first (if present).
    - Parse lists like EmailAddresses which may include 'SMTP:'/'smtp:' prefixes.
    - Filter out X.500/legacyExchangeDN entries.
    """
    out = []
    seen = set()

    def add(addr: str):
        if not isinstance(addr, str):
            return
        addr = addr.strip()
        if not addr:
            return
        # Remove known type prefixes
        addr_no_type = _strip_type_prefix(addr)
        # Filter out legacy/X.500
        if _is_legacy_dn(addr_no_type):
            return
        # Only keep plausible SMTP addresses
        if not _is_smtp_addr(addr_no_type):
            return
        key = addr_no_type.lower()
        if key not in seen:
            seen.add(key)
            out.append(addr_no_type)

    # 1) Strong preference: Primary SMTP if present
    add(rec.get("PrimarySmtpAddress"))

    # 2) Other single-value fields (sometimes used)
    for k in ("SmtpAddress", "EmailAddress", "Email"):
        add(rec.get(k))

    # 3) Multi-value fields (often include typed entries like SMTP:/ X500:/ EX:)
    for k in ("EmailAddresses", "EmailAddressList"):
        vs = rec.get(k)
        if isinstance(vs, list):
            for v in vs:
                add(v)

    return out

def collect_phones(rec):
    pairs = []
    mapping = {
        "PrimaryTelephoneNumber": "VOICE",
        "BusinessTelephoneNumber": "WORK,VOICE",
        "Business2TelephoneNumber": "WORK,VOICE",
        "HomeTelephoneNumber": "HOME,VOICE",
        "Home2TelephoneNumber": "HOME,VOICE",
        "MobileTelephoneNumber": "CELL,VOICE",
        "PagerTelephoneNumber": "PAGER",
        "BusinessFaxNumber": "WORK,FAX",
        "HomeFaxNumber": "HOME,FAX",
        "AssistantTelephoneNumber": "WORK,VOICE",
        "CallbackTelephoneNumber": "VOICE",
        "CompanyMainTelephoneNumber": "WORK,VOICE",
        "OtherTelephoneNumber": "VOICE",
    }
    for k, params in mapping.items():
        v = rec.get(k)
        if isinstance(v, str) and v:
            pairs.append((params, v))
    return pairs

def collect_addresses(rec):
    addrs = []
    b_street = rec.get("BusinessAddressStreet") or rec.get("StreetAddress") or ""
    b_city   = rec.get("BusinessAddressCity") or rec.get("Locality") or ""
    b_state  = rec.get("BusinessAddressStateOrProvince") or rec.get("StateOrProvince") or ""
    b_post   = rec.get("BusinessAddressPostalCode") or rec.get("PostalCode") or ""
    b_ctry   = rec.get("BusinessAddressCountry") or rec.get("Country") or ""
    if any([b_street, b_city, b_state, b_post, b_ctry]):
        addrs.append(("WORK", ("", "", b_street, b_city, b_state, b_post, b_ctry), None))
    h_street = rec.get("HomeAddressStreet") or ""
    h_city   = rec.get("HomeAddressCity") or ""
    h_state  = rec.get("HomeAddressStateOrProvince") or ""
    h_post   = rec.get("HomeAddressPostalCode") or ""
    h_ctry   = rec.get("HomeAddressCountry") or ""
    if any([h_street, h_city, h_state, h_post, h_ctry]):
        addrs.append(("HOME", ("", "", h_street, h_city, h_state, h_post, h_ctry), None))
    return addrs

def record_to_vcard(rec) -> str:
    lines = ["BEGIN:VCARD", "VERSION:3.0"]
    family, given, middle, prefix, suffix = build_name_components(rec)
    lines.append(fold_line(f"N:{v_escape(family)};{v_escape(given)};{v_escape(middle)};{v_escape(prefix)};{v_escape(suffix)}"))
    fn = rec.get("DisplayName") or " ".join([p for p in (prefix, given, middle, family, suffix) if p])
    add_if(lines, "FN", fn)
    org = rec.get("CompanyName") or ""
    dept = rec.get("DepartmentName") or ""
    if org and dept:
        lines.append(fold_line(f"ORG:{v_escape(org)};{v_escape(dept)}"))
    elif org:
        add_if(lines, "ORG", org)
    add_if(lines, "TITLE", rec.get("Title"))
    add_if(lines, "ROLE", rec.get("Profession") or rec.get("JobRole"))
    emails = collect_emails(rec)
    if emails:
        add_if(lines, "EMAIL", emails[0], params=["TYPE=INTERNET", "TYPE=PREF"])
        for e in emails[1:]:
            add_if(lines, "EMAIL", e, params=["TYPE=INTERNET"])
    for params, number in collect_phones(rec):
        add_if(lines, "TEL", number, params=[f"TYPE={params}"])
    for kind, adr, _ in collect_addresses(rec):
        po, ext, street, city, region, code, country = adr
        adr_value = ";".join(v_escape(x) for x in (po, ext, street, city, region, code, country))
        lines.append(fold_line(f"ADR;TYPE={kind}:{adr_value}"))
    add_if(lines, "URL", rec.get("WebPage") or rec.get("BusinessHomePage"))
    add_if(lines, "X-ASSISTANT", rec.get("Assistant"))
    add_if(lines, "X-OFFICE-LOCATION", rec.get("OfficeLocation"))
    note_bits = []
    for key in ("ManagerName", "SpouseName", "Hobby", "Notes"):
        if rec.get(key):
            note_bits.append(f"{key}: {rec[key]}")
    if note_bits:
        add_if(lines, "NOTE", " | ".join(note_bits))
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"

def write_vcards(records, out_path: str):
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        for rec in records:
            f.write(record_to_vcard(rec))

# ---------- main ----------
if __name__ == "__main__":
    in_path = sys.argv[1] if len(sys.argv) > 1 else "udetails.oab"
    out_path = "contacts.vcf"
    records = parse_oab_details(in_path)
    write_vcards(records, out_path)
    print(f"Exported {len(records)} contacts to {out_path}")
