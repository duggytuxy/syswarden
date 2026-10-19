"""A green process exit must not conceal absent adversarial evidence."""

import json
import unittest

import unprivileged_controls as gate


def encode(events):
    return b"\n".join(json.dumps(event).encode() for event in events)


def complete_report():
    events = [{"Action": "start", "Package": gate.PACKAGE}]
    for test in sorted(gate.required_tests()):
        events.extend({"Action": action, "Package": gate.PACKAGE, "Test": test} for action in ("run", "pass"))
    events.append({"Action": "pass", "Package": gate.PACKAGE})
    return events


class CrossUIDEvidenceTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(gate.verify(encode(complete_report())), 146)

    def test_missing_each_case(self):
        for test in gate.required_tests():
            with self.subTest(test=test):
                events = [e for e in complete_report() if e.get("Test") != test]
                with self.assertRaises(ValueError):
                    gate.verify(encode(events))

    def test_bad_transitions(self):
        for action in ("skip", "fail", "run", "output", "unknown"):
            with self.subTest(action=action):
                events = complete_report()
                events[2]["Action"] = action
                with self.assertRaises(ValueError):
                    gate.verify(encode(events))

    def test_empty_truncated_oversized_and_wrong_identity(self):
        fixtures = [b"", b"{}", b"[]", b"not-json", b"x" * (gate.MAX_REPORT_BYTES + 1)]
        events = complete_report()
        fixtures.extend(encode(events[:i]) for i in range(len(events)))
        events[1]["Package"] = "unrelated-package"
        fixtures.append(encode(events))
        events = complete_report()
        events[1]["Test"] = "unrelated-test"
        fixtures.append(encode(events))
        for fixture in fixtures:
            with self.assertRaises(ValueError):
                gate.verify(fixture)

    def test_duplicate_results_and_post_completion_data(self):
        events = complete_report()
        for extra, index in ((events[2], 3), (events[0], 1), (events[-1], len(events)), (events[1], len(events))):
            with self.assertRaises(ValueError):
                gate.verify(encode(events[:index] + [extra] + events[index:]))


if __name__ == "__main__":
    unittest.main()
