import unittest

import parsing.mime_multipart


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

    def test_find_existing_header(self):
        packet_text = """--gc0pJq08jU534c
Content-Id: n2ContentId1
Content-Type: application/vnd.3gpp.ngap"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        found_header = parsing.mime_multipart.find_header('Content-Id', msg)
        self.assertEqual(found_header, 'n2ContentId1')

    def test_find_non_existing_header(self):
        packet_text = """--gc0pJq08jU534c
Content-Id: n2ContentId1
Content-Type: application/vnd.3gpp.ngap"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text)[0]
        self.assertIsNotNone(msg)  # add assertion here
        found_header = parsing.mime_multipart.find_header('Content-test', msg)
        self.assertEqual(found_header, '')

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

    def test_with_single_part_none(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1

{"n1MessageContainer":"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text, single_part=True)

    def test_with_single_part_1(self):
        packet_text = """Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1

{"n1MessageContainer":"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text, single_part=True)[0]
        print(msg)
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, None)
        self.assertEqual(msg.payload, '{"n1MessageContainer":')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/vnd.3gpp.ngap')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'n2ContentId1')

    def test_with_single_part_2(self):
        packet_text = """Content-Type: application/json
Content-ID: json
Content-Transfer-Encoding: string

{"hoState":"PREPARING","n2SmInfo":{"contentId":"PduSessionResourceSetupRequestTransfer"},"n2SmInfoType":"PDU_RES_SETUP_REQ"}"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text, single_part=True)[0]
        print(msg)
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, None)
        self.assertEqual(msg.payload,
                         '{"hoState":"PREPARING","n2SmInfo":{"contentId":"PduSessionResourceSetupRequestTransfer"},"n2SmInfoType":"PDU_RES_SETUP_REQ"}')
        self.assertEqual(msg.mime_headers[0].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[0].value, 'application/json')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Id')
        self.assertEqual(msg.mime_headers[1].value, 'json')
        self.assertEqual(msg.mime_headers[2].name, 'Content-Transfer-Encoding')
        self.assertEqual(msg.mime_headers[2].value, 'string')

    def test_free5gc_multipart(self):
        packet_text = """--------------------------6dbf38bf08f8d96f
Content-Disposition: attachment; name="jsonData"
Content-Type: application/json

{
	"vsmfReleaseOnly":	false
}
--------------------------6dbf38bf08f8d96f--

"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text, single_part=False)[0]
        print(msg)
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, '------------------------6dbf38bf08f8d96f')
        self.assertEqual(msg.payload,
"""{
	"vsmfReleaseOnly":	false
}""")
        self.assertEqual(msg.mime_headers[0].name, 'Content-Disposition')
        self.assertEqual(msg.mime_headers[0].value, 'attachment; name="jsonData"')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[1].value, 'application/json')

    def test_free5gc_multipart_2(self):
        packet_text = """--------------------------6dbf38bf08f8d96f
Content-Disposition: attachment; name="jsonData"
Content-Type: application/json

{
	"vsmfReleaseOnly":	false
}
--------------------------6dbf38bf08f8d96f
Content-Disposition: attachment; name="test_data"
Content-Type: application/json

{
	"test_parameter":	false
}
--------------------------6dbf38bf08f8d96f--

"""
        msg = parsing.mime_multipart.parse_multipart_mime(packet_text, single_part=False)[0]
        print(msg)
        self.assertIsNotNone(msg)  # add assertion here
        self.assertEqual(msg.boundary, '------------------------6dbf38bf08f8d96f')
        self.assertEqual(msg.payload,
"""{
	"vsmfReleaseOnly":	false
}""")
        self.assertEqual(msg.mime_headers[0].name, 'Content-Disposition')
        self.assertEqual(msg.mime_headers[0].value, 'attachment; name="jsonData"')
        self.assertEqual(msg.mime_headers[1].name, 'Content-Type')
        self.assertEqual(msg.mime_headers[1].value, 'application/json')

if __name__ == '__main__':
    unittest.main()
