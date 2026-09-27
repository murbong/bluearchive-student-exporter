"""Export your running Blue Archive Steam client's student data to CSV.

Only reads process memory. No injection, memory writes, proxy, or game API calls.
Python 3.10+, Windows x64. See README.md for limitations.
"""
import argparse
import csv
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

NAMES_URL = 'https://schaledb.com/data/kr/students.json'
MAX_JSON_CHARS = 8 * 1024 * 1024


def login_packet(text):
    """Accept only a complete login response, never a request/session envelope."""
    try:
        obj, _ = json.JSONDecoder().raw_decode(text)
        if not isinstance(obj, dict) or obj.get('protocol') != 'Account_LoginSync':
            return None
        packet = json.loads(obj['packet']) if isinstance(obj['packet'], str) else obj['packet']
        students = packet['CharacterListResponse']['CharacterDBs']
        if not isinstance(students, list) or not students:
            return None
        if any(not isinstance(s, dict) or 'UniqueId' not in s or 'ServerId' not in s for s in students):
            return None
        # Keep only data needed for the export. No friend codes, sessions, or billing.
        wanted = ('ServerTimeTicks', 'CharacterListResponse',
                  'EquipmentItemListResponse', 'CharacterGearListResponse')
        return {key: packet[key] for key in wanted if key in packet}
    except (ValueError, TypeError, KeyError, RecursionError):
        return None


def find_pid():
    result = subprocess.run(
        ['tasklist', '/FI', 'IMAGENAME eq BlueArchive.exe', '/FO', 'CSV', '/NH'],
        capture_output=True, text=True, errors='replace', check=True)
    matches = [int(row[1]) for row in csv.reader(io.StringIO(result.stdout))
               if len(row) > 1 and row[0].lower() == 'bluearchive.exe']
    if len(matches) != 1:
        raise RuntimeError('Exactly one BlueArchive.exe must be running. Log in to the lobby first.')
    return matches[0]


def read_login_response(pid):
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        raise RuntimeError('Live reading requires Windows and 64-bit Python.')
    class MemoryInfo(C.Structure):
        _fields_ = [('BaseAddress', C.c_void_p), ('AllocationBase', C.c_void_p),
                    ('AllocationProtect', W.DWORD), ('PartitionId', W.WORD),
                    ('RegionSize', C.c_size_t), ('State', W.DWORD),
                    ('Protect', W.DWORD), ('Type', W.DWORD)]
    api = C.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes, api.OpenProcess.restype = [W.DWORD, W.BOOL, W.DWORD], W.HANDLE
    api.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MemoryInfo), C.c_size_t]
    api.VirtualQueryEx.restype = C.c_size_t
    api.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    api.ReadProcessMemory.restype = W.BOOL
    api.CloseHandle.argtypes = [W.HANDLE]
    handle = api.OpenProcess(0x1010, False, pid)  # QUERY_LIMITED_INFORMATION | VM_READ
    if not handle:
        raise C.WinError(C.get_last_error())

    def read(address, size):
        buffer = C.create_string_buffer(size)
        count = C.c_size_t()
        api.ReadProcessMemory(handle, address, buffer, size, C.byref(count))
        return buffer.raw[:count.value]

    patterns = [(text.encode(encoding), encoding)
                for text in ('{"protocol":"Account_LoginSync"', '{"protocol": "Account_LoginSync"')
                for encoding in ('utf-16-le', 'utf-8')]
    latest = None
    address = 0
    try:
        while address < 0x7FFFFFFFFFFF:
            region = MemoryInfo()
            if not api.VirtualQueryEx(handle, address, C.byref(region), C.sizeof(region)):
                break
            base, size = region.BaseAddress or 0, region.RegionSize
            if not size:
                break
            address = base + size
            # Committed, private, readable pages; never change page protection.
            if region.State != 0x1000 or region.Type != 0x20000 or region.Protect & 0x101:
                continue
            if region.Protect & 0xff not in (2, 4, 8, 0x20, 0x40, 0x80):
                continue
            for offset in range(0, size, 4 * 1024 * 1024):
                start = base + offset
                block = read(start, min(4 * 1024 * 1024 + 128, size - offset))
                for marker, encoding in patterns:
                    pos = block.find(marker)
                    while pos >= 0:
                        pointer = start + pos
                        if encoding == 'utf-16-le':
                            # IL2CPP System.String stores Int32 length before UTF-16 chars.
                            prefix = read(pointer - 4, 4)
                            length = int.from_bytes(prefix, 'little')
                            raw = read(pointer, length * 2) if len(prefix) == 4 and 20 <= length <= MAX_JSON_CHARS else b''
                        else:
                            raw = read(pointer, min(MAX_JSON_CHARS, address - pointer)).split(b'\0', 1)[0]
                        found = login_packet(raw.decode(encoding, errors='replace')) if raw else None
                        if found and (latest is None or found.get('ServerTimeTicks', 0) > latest.get('ServerTimeTicks', 0)):
                            latest = found
                        pos = block.find(marker, pos + len(marker))
    finally:
        api.CloseHandle(handle)
    if latest is None:
        raise RuntimeError('Login response not found. Restart the game, log in, and run again promptly. No output was written.')
    return latest


def load_names(path=None, offline=False):
    if offline:
        return {}
    if path:
        data = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    else:
        # Fixed public URL. No account values, credentials, or IDs are transmitted.
        request = urllib.request.Request(NAMES_URL, headers={'User-Agent': 'bluearchive-student-exporter'})
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.load(response)
    items = data.values() if isinstance(data, dict) else data
    return {int(item['Id']): item for item in items}


def unique_index(records, field):
    result = {}
    for record in records:
        key = record[field]
        if key in result:
            raise ValueError(f'Duplicate {field}; cannot safely join records.')
        result[key] = record
    return result


def make_rows(packet, names):
    characters = packet['CharacterListResponse']
    students = characters['CharacterDBs']
    unique_index(students, 'UniqueId')
    unique_index(students, 'ServerId')
    equipment = unique_index(packet['EquipmentItemListResponse']['EquipmentDBs'], 'ServerId')
    weapons = unique_index(characters['WeaponDBs'], 'BoundCharacterServerId')
    gears = unique_index(packet['CharacterGearListResponse']['GearDBs'], 'BoundCharacterServerId')
    ticks = packet.get('ServerTimeTicks')
    # .NET ticks do not encode a timezone. Do not mislabel server-local time as UTC.
    captured = (datetime(1, 1, 1) + timedelta(microseconds=ticks // 10)).isoformat() if ticks else ''
    rows = []
    for student in students:
        uid, sid = student['UniqueId'], student['ServerId']
        reference = names.get(uid, {})
        weapon, gear = weapons.get(sid), gears.get(sid)
        # Missing properties below are protocol default values, not missing rows.
        row = {'학생ID': uid, '이름': reference.get('Name', f'ID {uid}'),
               '레벨': student.get('Level', 1), '경험치': student.get('Exp', 0),
               '성급': student.get('StarGrade', 1), '인연랭크': student.get('FavorRank', 1),
               '인연경험치': student.get('FavorExp', 0),
               'EX스킬': student.get('ExSkillLevel', 1), '기본스킬': student.get('PublicSkillLevel', 1),
               '강화스킬': student.get('PassiveSkillLevel', 1), '서브스킬': student.get('ExtraPassiveSkillLevel', 1),
               '전용무기보유': bool(weapon), '전용무기성급': weapon.get('StarGrade', 1) if weapon else 0,
               '전용무기레벨': weapon.get('Level', 1) if weapon else 0,
               '전용무기경험치': weapon.get('Exp', 0) if weapon else 0,
               '애용품보유': bool(gear), '애용품티어': gear.get('Tier', 1) if gear else 0,
               '애용품레벨': gear.get('Level', 1) if gear else 0}
        slots = student.get('EquipmentServerIds', [0, 0, 0])
        if len(slots) != 3:
            raise ValueError('Expected three equipment slots; unsupported schema.')
        for slot, equipment_id in enumerate(slots, 1):
            equipped = equipment.get(equipment_id) if equipment_id else None
            if equipment_id and equipped is None:
                raise ValueError('Equipped item not present in equipment list.')
            if equipped and equipped.get('BoundCharacterServerId') != sid:
                raise ValueError('Equipment binding mismatch.')
            row[f'장비{slot}ID'] = equipped['UniqueId'] if equipped else 0
            row[f'장비{slot}티어'] = equipped.get('Tier', 1) if equipped else 0
            row[f'장비{slot}레벨'] = equipped.get('Level', 1) if equipped else 0
        potentials = student.get('PotentialStats', {})
        for key, name in [('1', '체력'), ('2', '공격력'), ('3', '치유력')]:
            row[f'잠재력_{name}'] = potentials.get(key, 0)
        row['즐겨찾기'] = student.get('IsFavorite', False)
        row['로그인응답시각_서버'] = captured
        rows.append(row)
    return sorted(rows, key=lambda row: (-row['레벨'], -row['성급'], row['이름']))


def write_csv(rows, path):
    if not rows:
        raise ValueError('No students to export.')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # BOM makes Korean names work when opened directly in Windows Excel.
    with path.open('x', encoding='utf-8-sig', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: "'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@', '\t', '\r', '\n')) else value
                             for key, value in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, help='Explicit BlueArchive.exe PID')
    parser.add_argument('--output', default='bluearchive-students.csv')
    parser.add_argument('--snapshot', help='Read a local Account_LoginSync packet JSON instead of live memory')
    parser.add_argument('--names-json', help='Use a local SchaleDB student-name file')
    parser.add_argument('--offline', action='store_true', help='No network access; use numeric student IDs as names')
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        parser.error('Output already exists. Choose another --output path to preserve the earlier export.')
    try:
        if args.snapshot:
            packet = json.loads(Path(args.snapshot).read_text(encoding='utf-8-sig'))
        else:
            if os.name != 'nt':
                raise RuntimeError('Live reading is available on Windows only.')
            packet = read_login_response(args.pid or find_pid())
        rows = make_rows(packet, load_names(args.names_json, args.offline))
        write_csv(rows, output)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Export failed: {error}', file=sys.stderr)
        return 1
    print(f'Exported {len(rows)} students to {output.resolve()}')
    print('Snapshot reflects the latest login response still in memory, not subsequent upgrades.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
