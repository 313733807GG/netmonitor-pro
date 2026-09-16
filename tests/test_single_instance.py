# -*- coding: utf-8 -*-
import os
import time
import unittest

from app import acquire_instance_lock, instance_lock_path, release_instance_lock


class SingleInstanceTests(unittest.TestCase):
    def setUp(self):
        self.base = os.path.abspath(f"test-instance-lock-{os.getpid()}-{time.time_ns()}")

    def tearDown(self):
        product = os.path.join(self.base, "NetMonitorPro")
        for name in ("netmonitor.lock", "netmonitor-smoketest.lock"):
            try:
                os.remove(os.path.join(product, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(product)
        except FileNotFoundError:
            pass
        try:
            os.rmdir(self.base)
        except FileNotFoundError:
            pass

    def test_product_lock_is_independent_of_executable_location(self):
        expected = os.path.join(self.base, "NetMonitorPro", "netmonitor.lock")
        self.assertEqual(instance_lock_path(False, self.base), expected)
        self.assertNotEqual(
            instance_lock_path(False, self.base),
            instance_lock_path(True, self.base),
        )

    def test_second_instance_is_rejected_until_first_releases(self):
        first = acquire_instance_lock(False, self.base)
        self.assertIsNotNone(first)
        try:
            self.assertIsNone(acquire_instance_lock(False, self.base))
        finally:
            release_instance_lock(first)
        third = acquire_instance_lock(False, self.base)
        self.assertIsNotNone(third)
        release_instance_lock(third)


if __name__ == "__main__":
    unittest.main()
