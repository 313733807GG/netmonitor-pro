import unittest
from unittest.mock import patch

import app


class ElevationTests(unittest.TestCase):
    def test_windows_accepts_default_elevated_relaunch(self):
        calls = []

        def accepted(*args):
            calls.append(args)
            return 42

        with patch.object(app, "is_user_admin", return_value=False):
            self.assertTrue(app.request_elevated_relaunch(accepted))

        self.assertEqual(calls[0][1], "runas")
        self.assertIn("--elevated-relaunch", calls[0][3])

    def test_cancelled_uac_returns_false_for_normal_mode_fallback(self):
        with patch.object(app, "is_user_admin", return_value=False):
            self.assertFalse(app.request_elevated_relaunch(lambda *args: 5))


if __name__ == "__main__":
    unittest.main()
