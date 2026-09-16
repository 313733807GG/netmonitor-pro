import ctypes
import struct
import unittest

from etw.evntcons import EVENT_RECORD
from traffic_capture import ProcessTrafficMonitor


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


def make_record(event_id, pid, size):
    record = EVENT_RECORD()
    payload = ctypes.create_string_buffer(struct.pack("<II", pid, size))
    record.EventHeader.EventDescriptor.Id = event_id
    record.UserDataLength = 8
    record.UserData = ctypes.addressof(payload)
    return record, payload


class ProcessTrafficMonitorTests(unittest.TestCase):
    def test_raw_tcp_and_udp_events_are_split_by_direction(self):
        clock = FakeClock()
        monitor = ProcessTrafficMonitor(clock=clock)

        tcp_up, tcp_up_payload = make_record(10, 120, 1000)
        udp_up, udp_up_payload = make_record(42, 120, 500)
        tcp_down, tcp_down_payload = make_record(27, 120, 3000)
        udp_down, udp_down_payload = make_record(59, 121, 4000)
        # Keep payload references alive while the callback reads their addresses.
        self.assertTrue(all((tcp_up_payload, udp_up_payload, tcp_down_payload, udp_down_payload)))

        for record in (tcp_up, udp_up, tcp_down, udp_down):
            monitor._on_raw_event((0, ctypes.pointer(record)))

        clock.value = 2.0
        rates = monitor.snapshot()
        self.assertEqual(rates[120], (750.0, 1500.0))
        self.assertEqual(rates[121], (0.0, 2000.0))
        self.assertEqual(monitor.event_count, 4)

    def test_non_transfer_and_short_events_are_ignored(self):
        clock = FakeClock()
        monitor = ProcessTrafficMonitor(clock=clock)

        connect, payload = make_record(12, 200, 999)
        monitor._on_raw_event((0, ctypes.pointer(connect)))

        short = EVENT_RECORD()
        short.EventHeader.EventDescriptor.Id = 10
        short.UserDataLength = 4
        short.UserData = ctypes.addressof(payload)
        monitor._on_raw_event((0, ctypes.pointer(short)))

        clock.value = 1.0
        self.assertEqual(monitor.snapshot(), {})
        self.assertEqual(monitor.invalid_event_count, 1)


if __name__ == "__main__":
    unittest.main()
