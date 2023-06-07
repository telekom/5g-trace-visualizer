import unittest

import parsing.mime_multipart


class test_multipart_mime(unittest.TestCase):
    def test_boundary1(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = parsing.mime_multipart.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group(2), 'gc0pJq08jU534c')
        self.assertEqual(match.group(3), 'application/vnd.3gpp.ngap')

    def test_boundary1_named_groups(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = parsing.mime_multipart.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.ngap')

    def test_boundary1_named_groups_2(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/json

{"n1MessageContainer":"""
        match = parsing.mime_multipart.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/json')

    def test_boundary1_named_groups_3(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.5gnas
Content-Id: n1ContentId1

"""
        match = parsing.mime_multipart.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.5gnas')
        self.assertEqual(match.group('content_id'), 'n1ContentId1')

    def test_boundary2_named_groups(self):
        packet_text = """--oiH7UJCrm4vEWMX70dIsiqFSAYBdme6zn39WMZftu_1_M9D80Ajho1cTLSIkMVSC
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = parsing.mime_multipart.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'oiH7UJCrm4vEWMX70dIsiqFSAYBdme6zn39WMZftu_1_M9D80Ajho1cTLSIkMVSC')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.ngap')


class test_multipart_mime_v2(unittest.TestCase):
    def test_no_payload(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

    def test_capitalization1(self):
        packet_text = """--gc0pJq08jU534c
Content-TYPE: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

    def test_header_order(self):
        packet_text = """--gc0pJq08jU534c
Content-Id: n2ContentId1
Content-Type: application/vnd.3gpp.ngap"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[1].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[0].value, 'n2ContentId1')

    def test_capitalization2(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-ID: n2ContentId1"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

    def test_with_payload(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1

{"n1MessageContainer":"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '{"n1MessageContainer":')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

    def test_two_messages(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1

{"n1MessageContainer":
--gc0pJq08jU534c
Content-Type: test

Test payload"""
        msgs = parsing.mime_multipart.parse_multipart_mime(packet_text)
        msg = msgs[0]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, '{"n1MessageContainer":')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

        msg = msgs[1]
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, 'gc0pJq08jU534c')
        self.assertEqual(msg.payload, 'Test payload')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'test')


if __name__ == '__main__':
    unittest.main()
