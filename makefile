# in a separate terminal do rm -rf. unlinkat is used here
# as a tracepoint.
# the config = cat /sys/kernel/debug/tracing/events/sys_enter_unlinkat/id
# read the man bpf, man perf_event_open,
# /home/prakhar/data/linux/linux-5.18/Documentation/bpf/instruction-set.rst
all:
	gcc bpf_example.c -o main
