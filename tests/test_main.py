# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2015 Jason Ish
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import os
import shutil
import subprocess
import tempfile
import unittest

import suricata.update.rule
from suricata.update import main


def has_python2():
    r = subprocess.call(["python2", "--version"],
                        stderr=open("/dev/null", "wb"),
                        stdout=open("/dev/null", "wb"))
    if r == 0:
        return True
    return False


def has_python3():
    r = subprocess.call(["python3", "--version"],
                        stderr=open("/dev/null", "wb"),
                        stdout=open("/dev/null", "wb"))
    if r == 0:
        return True
    return False


class TestRulecat(unittest.TestCase):
    """TestRuleCat"""
    def test_extract_tar(self):
        files = main.extract_tar("tests/emerging.rules.tar.gz")
        self.assertTrue(len(files) > 0)

    def test_extract_zip(self):
        files = main.extract_zip("tests/emerging.rules.zip")
        self.assertTrue(len(files) > 0)

    def test_try_extract(self):
        files = main.try_extract("tests/emerging.rules.zip")
        self.assertTrue(len(files) > 0)

        files = main.try_extract("tests/emerging.rules.tar.gz")
        self.assertTrue(len(files) > 0)

        files = main.try_extract("tests/emerging-current_events.rules")
        self.assertEqual(files, {})

    @unittest.skipIf(not has_python2(), "python2 not available")
    def test_run_python2(self):
        old_path = os.getcwd()
        try:
            os.chdir(os.path.dirname(os.path.realpath(__file__)))
            if os.path.exists("./tmp"):
                shutil.rmtree("tmp")
            os.makedirs("./tmp/rules")
            subprocess.check_call(
                ["/usr/bin/env",
                 "suricata-update",
                 "-c",
                 "./update.yaml",
                 "--url",
                 "file://%s/emerging.rules.tar.gz" % (os.getcwd()),
                 "--local",
                 "./rule-with-unicode.rules",
                 "--force",
                 "--output",
                 "./tmp/rules/",
                 "--yaml-fragment",
                 "./tmp/suricata-rules.yaml",
                 "--sid-msg-map",
                 "./tmp/sid-msg.map",
                 "--sid-msg-map-2",
                 "./tmp/sid-msg-v2.map",
                 "--no-test",
                 "--reload-command",
                 "true", ],
                stdout=open("./tmp/stdout", "wb"),
                stderr=open("./tmp/stderr", "wb"), )
            shutil.rmtree("tmp")
        except:
            if os.path.exists("./tmp/stdout"):
                print("STDOUT")
                print(open("./tmp/stdout").read())
            if os.path.exists("./tmp/stderr"):
                print("STDERR")
                print(open("./tmp/stderr").read())
            raise
        finally:
            os.chdir(old_path)

    @unittest.skipIf(not has_python3(), "python3 not available")
    def test_run_python3(self):
        old_path = os.getcwd()
        try:
            os.chdir(os.path.dirname(os.path.realpath(__file__)))
            if os.path.exists("./tmp"):
                shutil.rmtree("tmp")
            os.makedirs("./tmp/rules")
            subprocess.check_call(
                ["/usr/bin/env"
                 "suricata-update",
                 "-c",
                 "./update.yaml",
                 "--url",
                 "file://%s/emerging.rules.tar.gz" % (os.getcwd()),
                 "--local",
                 "./rule-with-unicode.rules",
                 "--force",
                 "--output",
                 "./tmp/rules/",
                 "--yaml-fragment",
                 "./tmp/suricata-rules.yaml",
                 "--sid-msg-map",
                 "./tmp/sid-msg.map",
                 "--sid-msg-map-2",
                 "./tmp/sid-msg-v2.map",
                 "--no-test",
                 "--reload-command",
                 "true", ],
                stdout=open("./tmp/stdout", "wb"),
                stderr=open("./tmp/stderr", "wb"), )
            shutil.rmtree("tmp")
        except:
            if os.path.exists("./tmp/stdout"):
                print("STDOUT")
                print(open("./tmp/stdout").read())
            if os.path.exists("./tmp/stderr"):
                print("STDERR")
                print(open("./tmp/stderr").read())
            raise
        finally:
            os.chdir(old_path)


class TestFetch(unittest.TestCase):
    """TestFetch"""

    def test_check_checksum(self):
        """Test that we detect when the checksum are the same. This is mainly
        to catch issues between Python 2 and 3.
        """
        fetch = main.Fetch(None)
        url = "file://%s/emerging.rules.tar.gz" % (
            os.path.dirname(os.path.realpath(__file__)))
        local_file = "%s/emerging.rules.tar.gz" % (
            os.path.dirname(os.path.realpath(__file__)))
        r = fetch.check_checksum(local_file, url)
        self.assertTrue(r)


class ThresholdProcessorTestCase(unittest.TestCase):
    """ThresholdProcessorTestCase"""
    processor = main.ThresholdProcessor()

    def test_extract_regex(self):
        processor = main.ThresholdProcessor()

        line = "suppress re:java"
        self.assertEquals("java", processor.extract_regex(line))

        line = 'suppress re:"vulnerable java version"'
        self.assertEquals("vulnerable java version",
                          processor.extract_regex(line))

        line = "suppress re:java, track <by_src|by_dst>, ip <ip|subnet>"
        self.assertEquals("java", processor.extract_regex(line))

        line = 'suppress re:"vulnerable java version", track <by_src|by_dst>, ip <ip|subnet>'
        self.assertEquals("vulnerable java version",
                          processor.extract_regex(line))

        line = 'threshold re:"vulnerable java version", type threshold, track by_dst, count 1, seconds 10'
        self.assertEquals("vulnerable java version",
                          processor.extract_regex(line))

    def test_replace(self):
        rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule = suricata.update.rule.parse(rule_string)

        line = "suppress re:windows"
        self.assertEquals("suppress gen_id 1, sig_id 2020757",
                          self.processor.replace(line, rule))

        line = 'threshold re:"ET MALWARE Windows", type threshold, ' \
               'track by_dst, count 1, seconds 10'
        self.assertEquals(
            "threshold gen_id 1, sig_id 2020757, type threshold, track by_dst, count 1, seconds 10",
            self.processor.replace(line, rule))

        line = 'threshold re:malware, type threshold, track by_dst, count 1, ' \
               'seconds 10'
        self.assertEquals(
            "threshold gen_id 1, sig_id 2020757, type threshold, "
            "track by_dst, count 1, seconds 10",
            self.processor.replace(line, rule))


class ModifyRuleFilterTestCase(unittest.TestCase):
    """ModifyRuleFilterTestCase"""
    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_id_match(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = '2020757 "\|0d 0a\|" "|ff ff|"'
        rule_filter = main.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter is not None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.filter(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

    def test_re_match(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "\|0d 0a\|" "|ff ff|"'
        rule_filter = main.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter is not None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.filter(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

    def test_re_backref_one(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "(alert)(.*)" "drop\\2"'
        filter = main.ModifyRuleFilter.parse(line)
        self.assertTrue(filter is not None)
        self.assertTrue(filter.match(rule0))
        rule1 = filter.filter(rule0)
        expected = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        self.assertEqual(str(rule1), expected)

    def test_re_backref_two(self):
        rule0 = suricata.update.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "(alert)(.*)(from_server)(.*)" "drop\\2to_client\\4"'
        filter = main.ModifyRuleFilter.parse(line)
        self.assertTrue(filter is not None)
        self.assertTrue(filter.match(rule0))
        rule1 = filter.filter(rule0)
        expected = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        self.assertEqual(str(rule1), expected)

    def test_drop_to_alert(self):
        rule_in = suricata.update.rule.parse(self.rule_string)
        self.assertIsNotNone(rule_in)

        f = main.ModifyRuleFilter.parse(
            'group:emerging-trojan.rules "^alert" "drop"')
        self.assertIsNotNone(f)

        rule_out = f.filter(rule_in)
        self.assertTrue(rule_out.format().startswith("drop"))

    def test_oinkmaster_backticks(self):
        f = main.ModifyRuleFilter.parse(
            '* "^drop(.*)noalert(.*)" "alert${1}noalert${2}"')
        rule_in = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; noalert; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule_out = f.filter(suricata.update.rule.parse(rule_in))
        self.assertEqual(
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; noalert; classtype:trojan-activity; sid:2020757; rev:2;)""",
            rule_out.format())

    def test_oinkmaster_backticks_not_noalert(self):
        f = main.ModifyRuleFilter.parse(
            'modifysid * "^drop(.*)noalert(.*)" | "alert${1}noalert${2}"')
        rule_in = """drop http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule_out = f.filter(suricata.update.rule.parse(rule_in))
        self.assertEqual(rule_in, rule_out.format())

    def test_oinkmaster_modify_group_name(self):
        """Test an Oinkmaster style modification line using a group name."""
        f = main.ModifyRuleFilter.parse(
            'modifysid botcc.rules "^alert" | "drop"')
        rule_in = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,to_client; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule = suricata.update.rule.parse(rule_in, "rules/botcc.rules")
        rule_out = f.filter(rule)
        self.assertTrue(rule_out.format().startswith("drop"))


class GroupMatcherTestCase(unittest.TestCase):
    """GroupMatcherTestCase"""
    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_match(self):
        rule = suricata.update.rule.parse(self.rule_string,
                                          "rules/malware.rules")
        matcher = main.parse_rule_match("group: malware.rules")
        self.assertEquals(matcher.__class__, suricata.update.main.GroupMatcher)
        self.assertTrue(matcher.match(rule))

        # Test match of just the group basename.
        matcher = main.parse_rule_match("group: malware")
        self.assertEquals(matcher.__class__, suricata.update.main.GroupMatcher)
        self.assertTrue(matcher.match(rule))


class FilenameMatcherTestCase(unittest.TestCase):
    """FilenameMatcherTestCase"""
    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_match(self):
        rule = suricata.update.rule.parse(self.rule_string,
                                          "rules/trojan.rules")
        matcher = main.parse_rule_match("filename: */trojan.rules")
        self.assertEquals(matcher.__class__,
                          suricata.update.main.FilenameMatcher)
        self.assertTrue(matcher.match(rule))


class DropRuleFilterTestCase(unittest.TestCase):
    """DropRuleFilterTestCase"""
    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_enabled_rule(self):
        rule0 = suricata.update.rule.parse(self.rule_string,
                                           "rules/malware.rules")
        id_matcher = main.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = main.DropRuleFilter(id_matcher)
        rule1 = drop_filter.filter(rule0)
        self.assertEquals("drop", rule1.action)
        self.assertTrue(rule1.enabled)
        self.assertTrue(str(rule1).startswith("drop"))

    def test_disabled_rule(self):
        rule0 = suricata.update.rule.parse("# " + self.rule_string,
                                           "rules/malware.rules")
        id_matcher = main.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = main.DropRuleFilter(id_matcher)
        rule1 = drop_filter.filter(rule0)
        self.assertEquals("drop", rule1.action)
        self.assertFalse(rule1.enabled)
        self.assertTrue(str(rule1).startswith("# drop"))

    def test_drop_noalert(self):
        """ Test the rules with "noalert" are not marked as drop. """

        rule_without_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule_with_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; flowbits: noalert; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule = suricata.update.rule.parse(rule_without_noalert)
        matcher = main.IdRuleMatcher.parse("2016659")
        filter = main.DropRuleFilter(matcher)
        self.assertTrue(filter.match(rule))

        rule = suricata.update.rule.parse(rule_with_noalert)
        matcher = main.IdRuleMatcher.parse("2016659")
        filter = main.DropRuleFilter(matcher)
        self.assertFalse(filter.match(rule))
