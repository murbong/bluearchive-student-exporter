import csv
import json
from pathlib import Path
import tempfile
import unittest

import export_students as exporter


def fixture():
    # Synthetic records only. No captured account data belongs in this repository.
    return {
        'ServerTimeTicks': 638000000000000000,
        'CharacterListResponse': {
            'CharacterDBs': [{'UniqueId': 10001, 'ServerId': 101,
                             'Level': 20, 'EquipmentServerIds': [201, 0, 0],
                             'PotentialStats': {'1': 2, '2': 3, '3': 4}}],
            'WeaponDBs': [{'BoundCharacterServerId': 101}]},
        'EquipmentItemListResponse': {'EquipmentDBs': [
            {'ServerId': 201, 'UniqueId': 1, 'BoundCharacterServerId': 101,
             'Tier': 3, 'Level': 20}]},
        'CharacterGearListResponse': {'GearDBs': []}}


class ExportTests(unittest.TestCase):
    def test_response_whitelist(self):
        packet = fixture()
        packet['AccountDB'] = {'Secret': 'do-not-export'}
        for wrapped in (packet, json.dumps(packet)):
            result = exporter.login_packet(json.dumps(
                {'protocol': 'Account_LoginSync', 'packet': wrapped}))
            self.assertEqual(result, fixture())

    def test_invalid_or_unrelated_packets(self):
        for text in ('{', 'null', '[]', '{}',
                     '{"protocol":"Account_LoginSync","packet":null}',
                     json.dumps({'protocol': 'Other', 'packet': fixture()})):
            self.assertIsNone(exporter.login_packet(text))

    def test_empty_students_rejected(self):
        packet = fixture()
        packet['CharacterListResponse']['CharacterDBs'] = []
        self.assertIsNone(exporter.login_packet(json.dumps(
            {'protocol': 'Account_LoginSync', 'packet': packet})))

    def test_joins_and_missing_slots(self):
        row = exporter.make_rows(fixture(), {10001: {'Name': '테스트'}})[0]
        self.assertEqual(row['이름'], '테스트')
        self.assertEqual((row['장비1티어'], row['장비1레벨'], row['장비2ID']), (3, 20, 0))
        self.assertTrue(row['전용무기보유'])
        self.assertEqual(row['전용무기성급'], 1)
        self.assertFalse(row['애용품보유'])
        self.assertEqual([row['잠재력_' + key] for key in ('체력', '공격력', '치유력')], [2, 3, 4])
        self.assertEqual(len(row), 32)
        self.assertFalse(any(key in row for key in ('ServerId', 'SessionKey', 'AccountId')))

    def test_no_weapon_is_distinct_from_default_weapon(self):
        packet = fixture()
        packet['CharacterListResponse']['WeaponDBs'] = []
        row = exporter.make_rows(packet, {})[0]
        self.assertFalse(row['전용무기보유'])
        self.assertEqual(row['전용무기성급'], 0)
        self.assertEqual(row['이름'], 'ID 10001')

    def test_duplicate_students_rejected(self):
        packet = fixture()
        packet['CharacterListResponse']['CharacterDBs'] *= 2
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            exporter.make_rows(packet, {})

    def test_equipment_missing_or_wrong_binding_rejected(self):
        for records in ([], [{'ServerId': 201, 'BoundCharacterServerId': 999}]):
            packet = fixture()
            packet['EquipmentItemListResponse']['EquipmentDBs'] = records
            with self.assertRaises(ValueError):
                exporter.make_rows(packet, {})

    def test_unexpected_slot_count_rejected(self):
        packet = fixture()
        packet['CharacterListResponse']['CharacterDBs'][0]['EquipmentServerIds'] = [201]
        with self.assertRaisesRegex(ValueError, 'three'):
            exporter.make_rows(packet, {})

    def test_csv_bom_formula_escape_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'result.csv'
            exporter.write_csv([{'이름': '=1+1', '레벨': 20}], target)
            self.assertTrue(target.read_bytes().startswith(b'\xef\xbb\xbf'))
            with target.open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(list(csv.DictReader(stream)), [{'이름': "'=1+1", '레벨': '20'}])
            with self.assertRaises(FileExistsError):
                exporter.write_csv([{'이름': 'replace'}], target)

    def test_names_list_dict_and_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'names.json'
            for data in ([{'Id': 10001, 'Name': '테스트'}],
                         {'10001': {'Id': 10001, 'Name': '테스트'}}):
                path.write_text(json.dumps(data), encoding='utf-8')
                self.assertEqual(exporter.load_names(path)[10001]['Name'], '테스트')
            self.assertEqual(exporter.load_names('missing-file', offline=True), {})


if __name__ == '__main__':
    unittest.main()
