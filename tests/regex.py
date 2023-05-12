import unittest
import trace_visualizer


class test_multipart_mime(unittest.TestCase):
    def test_boundary1(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = trace_visualizer.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group(2), 'gc0pJq08jU534c')
        self.assertEqual(match.group(3), 'application/vnd.3gpp.ngap')


    def test_boundary1_named_groups(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = trace_visualizer.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.ngap')

    def test_boundary1_named_groups_2(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/json

{"n1MessageContainer":"""
        match = trace_visualizer.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/json')

    def test_boundary1_named_groups_3(self):
        packet_text = """--gc0pJq08jU534c
Content-Type: application/vnd.3gpp.5gnas
Content-Id: n1ContentId1

"""
        match = trace_visualizer.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'gc0pJq08jU534c')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.5gnas')
        self.assertEqual(match.group('content_id'), 'n1ContentId1')

    def test_boundary2_named_groups(self):
        packet_text = """--oiH7UJCrm4vEWMX70dIsiqFSAYBdme6zn39WMZftu_1_M9D80Ajho1cTLSIkMVSC
Content-Type: application/vnd.3gpp.ngap
Content-Id: n2ContentId1"""
        match = trace_visualizer.mime_multipart_payload_regex.match(packet_text)
        self.assertIsNotNone(match)  # add assertion here
        self.assertEqual(match.group('boundary'), 'oiH7UJCrm4vEWMX70dIsiqFSAYBdme6zn39WMZftu_1_M9D80Ajho1cTLSIkMVSC')
        self.assertEqual(match.group('content_type'), 'application/vnd.3gpp.ngap')

if __name__ == '__main__':
    unittest.main()
