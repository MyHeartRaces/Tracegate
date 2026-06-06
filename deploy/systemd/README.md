# Optional host services

`tracegate-clock-sync-from-rtc.timer` is an opt-in fallback for hosts where:

- NTP/UDP 123 is blocked;
- the host RTC has been verified against an external trusted clock;
- system clock drift is large enough to break timestamp-authenticated
  transports such as MTProto FakeTLS.

Install the service and timer in `/etc/systemd/system/`, then enable the timer.
Do not enable it on hosts with an untrusted or local-time RTC.
