#!/bin/bash

grep -inH "missing" log_ipsec/*.log
grep -inH "fail" log_ipsec/*.log
grep -inH "hardware" log_ipsec/*.log
grep -inH "killing" log_ipsec/*.log
