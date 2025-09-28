# oab_to_vcard.py
from struct import unpack
from io import BytesIO
import math
import binascii
import sys
from schema import PidTagSchema

# ---------- parsing helpers (same spirit as your script) ----------
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
                    # skip unknown by best-effort consuming a sized field if any
                    # (safer would be to know exact type; we just continue)
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
    # RFC 2426/6350 escaping
    return (s.replace("\\", "\\\\")
            .replace("\n", "\\n")
            .replace(",", "\\,")
            .replace(";", "\\;"))

def fold_line(line: str) -> str:
    """
    Fold to 75 octets per RFC. We approximate by 75 characters (safe for ASCII).
    Continuation lines start with one space.
    """
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

def collect_emails(rec):
    emails = []
    # Common fields seen in OAB/Exchange
    for k in ("PrimarySmtpAddress", "SmtpAddress", "EmailAddress", "Email"):
        v = rec.get(k)
        if isinstance(v, str) and v and v not in emails:
            emails.append(v)
    # Lists
    for k in ("EmailAddresses", "EmailAddressList"):
        vs = rec.get(k)
        if isinstance(vs, list):
            for v in vs:
                if isinstance(v, str) and v and v not in emails:
                    emails.append(v)
    return emails

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
    """Return list of (type, adr_tuple, label) for vCard ADR.
    ADR format: PO Box;Extended;Street;City;Region;PostalCode;Country
    """
    addrs = []
    # Business
    b_street = rec.get("BusinessAddressStreet") or rec.get("StreetAddress") or ""
    b_city   = rec.get("BusinessAddressCity") or rec.get("Locality") or ""
    b_state  = rec.get("BusinessAddressStateOrProvince") or rec.get("StateOrProvince") or ""
    b_post   = rec.get("BusinessAddressPostalCode") or rec.get("PostalCode") or ""
    b_ctry   = rec.get("BusinessAddressCountry") or rec.get("Country") or ""
    if any([b_street, b_city, b_state, b_post, b_ctry]):
        addrs.append(("WORK", ("", "", b_street, b_city, b_state, b_post, b_ctry), None))

    # Home
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

    # N / FN
    family, given, middle, prefix, suffix = build_name_components(rec)
    lines.append(fold_line(f"N:{v_escape(family)};{v_escape(given)};{v_escape(middle)};{v_escape(prefix)};{v_escape(suffix)}"))
    fn = rec.get("DisplayName") or " ".join([p for p in (prefix, given, middle, family, suffix) if p])
    add_if(lines, "FN", fn)

    # ORG / TITLE / ROLE / DEPT
    org = rec.get("CompanyName") or ""
    dept = rec.get("DepartmentName") or ""
    if org and dept:
        lines.append(fold_line(f"ORG:{v_escape(org)};{v_escape(dept)}"))
    elif org:
        add_if(lines, "ORG", org)
    add_if(lines, "TITLE", rec.get("Title"))
    add_if(lines, "ROLE", rec.get("Profession") or rec.get("JobRole"))

    # EMAIL(s)
    emails = collect_emails(rec)
    if emails:
        # mark first as PREF
        add_if(lines, "EMAIL", emails[0], params=["TYPE=INTERNET", "TYPE=PREF"])
        for e in emails[1:]:
            add_if(lines, "EMAIL", e, params=["TYPE=INTERNET"])

    # TEL(s)
    for params, number in collect_phones(rec):
        add_if(lines, "TEL", number, params=[f"TYPE={params}"])

    # ADR(s)
    for kind, adr, _label in collect_addresses(rec):
        po, ext, street, city, region, code, country = adr
        adr_value = ";".join(v_escape(x) for x in (po, ext, street, city, region, code, country))
        lines.append(fold_line(f"ADR;TYPE={kind}:{adr_value}"))

    # URL
    add_if(lines, "URL", rec.get("WebPage") or rec.get("BusinessHomePage"))

    # ORG extras
    add_if(lines, "X-ASSISTANT", rec.get("Assistant"))
    add_if(lines, "X-OFFICE-LOCATION", rec.get("OfficeLocation"))

    # NOTE
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

# ---------- CLI ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python oab_to_vcard.py udetails.oab [out.vcf] [max_records]")
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "contacts.vcf"
    maxrecs = int(sys.argv[3]) if len(sys.argv) > 3 else None

    records = parse_oab_details(in_path, max_records=maxrecs)
    write_vcards(records, out_path)
    print(f"Exported {len(records)} contacts to {out_path}")
