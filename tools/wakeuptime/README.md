# wakeuptime

## build

```
make
```

## run

```
$ sudo ./wakeuptime
Tracing blocked time (us) by kernel stack
^C
	target:          kworker/u4:2
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/1
	108870

	target:          sudo)
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/0
	447224

	target:          kworker/u4:2
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e13cd queue_work_on
	ffffffffa8b1903d cursor_timer_handler
	ffffffffa85716fc call_timer_fn
	ffffffffa8572ac3 __run_timers.part.0
	ffffffffa8572b7a run_timer_softirq
	ffffffffa94000d9 __softirqentry_text_start
	          waker: swapper/1
	210289

	target:          kworker/1:3
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/1
	71561

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8573492 hrtimer_wakeup
	ffffffffa8573a09 __hrtimer_run_queues
	ffffffffa8574821 hrtimer_interrupt
	ffffffffa84805b1 __sysvec_apic_timer_interrupt
	ffffffffa919fd0b sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa856bfa3 exit_to_user_mode_loop
	ffffffffa856c130 exit_to_user_mode_prepare
	          waker: wakeuptime
	87

	target:          sshd)
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/0
	447107

	target:          rcu_sched
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/0
	50

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8573492 hrtimer_wakeup
	ffffffffa8573a09 __hrtimer_run_queues
	ffffffffa8574821 hrtimer_interrupt
	ffffffffa84805b1 __sysvec_apic_timer_interrupt
	ffffffffa919fd0b sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	          waker: swapper/1
	236

	target:          containerd
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8573492 hrtimer_wakeup
	ffffffffa8573a09 __hrtimer_run_queues
	ffffffffa8574821 hrtimer_interrupt
	ffffffffa84805b1 __sysvec_apic_timer_interrupt
	ffffffffa919fd0b sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	          waker: swapper/0
	13327

	target:          kworker/1:3
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e13cd queue_work_on
	ffffffffa863bed5 bpf_prog_free
	ffffffffa863ef50 __bpf_prog_put_rcu
	ffffffffa8560a81 rcu_do_batch
	ffffffffa8561712 rcu_core
	ffffffffa8561a3e rcu_core_si
	          waker: swapper/1
	15601

	target:          rcu_sched
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8571092 process_timeout
	ffffffffa85716fc call_timer_fn
	ffffffffa8572ac3 __run_timers.part.0
	ffffffffa8572b7a run_timer_softirq
	ffffffffa94000d9 __softirqentry_text_start
	ffffffffa84c57b4 irq_exit_rcu
	ffffffffa919fd10 sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	          waker: swapper/0
	7937

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503d10 wake_up_state
	ffffffffa84d03ee complete_signal
	ffffffffa84d0d5f __send_signal
	ffffffffa84d30a9 send_signal
	ffffffffa84d3b80 do_send_sig_info
	ffffffffa84d44d5 __kill_pgrp_info
	ffffffffa84d4555 kill_pgrp
	ffffffffa8bf3d26 isig
	ffffffffa8bf401b n_tty_receive_signal_char
	          waker: kworker/u4:2
	447405

	target:          ksoftirqd/1
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa9400289 __softirqentry_text_start
	ffffffffa84c57b4 irq_exit_rcu
	ffffffffa919fd10 sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/1
	15673

	target:          kworker/1:3
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e13cd queue_work_on
	ffffffffc0302ccd drm_fb_helper_damage.isra.0
	ffffffffc03031c6 drm_fbdev_fb_imageblit
	ffffffffa8b208b1 soft_cursor
	ffffffffa8b20410 bit_cursor
	ffffffffa8b1bbb4 fb_flashcursor
	          waker: kworker/u4:2
	250024

	target:          kworker/u4:1
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc3e sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	          waker: wakeuptime
	73

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa86fc74f __handle_mm_fault
	ffffffffa86fcb98 handle_mm_fault
	ffffffffa849ead9 do_user_addr_fault
	ffffffffa91a0607 exc_page_fault
	          waker: wakeuptime
	85

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/0
	894617

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa85032d0 wake_up_q
	ffffffffa858b2f9 futex_wake
	ffffffffa858dc32 do_futex
	ffffffffa858e2d8 __x64_sys_futex
	ffffffffa919c74c do_syscall_64
	ffffffffa9200099 entry_SYSCALL_64_after_hwframe
	          waker: wakeuptime
	447272

	target:          kworker/0:1
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e24e9 delayed_work_timer_fn
	ffffffffa85716fc call_timer_fn
	ffffffffa8572a5d __run_timers.part.0
	ffffffffa8572b9b run_timer_softirq
	ffffffffa94000d9 __softirqentry_text_start
	ffffffffa84c57b4 irq_exit_rcu
	          waker: swapper/0
	136225

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8573492 hrtimer_wakeup
	ffffffffa8573a09 __hrtimer_run_queues
	ffffffffa8574821 hrtimer_interrupt
	ffffffffa84805b1 __sysvec_apic_timer_interrupt
	ffffffffa919fd0b sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa8516a20 init_entity_runnable_average
	ffffffffa84bbdf8 copy_process
	          waker: wakeuptime
	126

	target:          kworker/u4:2
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e24e9 delayed_work_timer_fn
	ffffffffa85716fc call_timer_fn
	ffffffffa8572a5d __run_timers.part.0
	ffffffffa8572b9b run_timer_softirq
	ffffffffa94000d9 __softirqentry_text_start
	ffffffffa84c57b4 irq_exit_rcu
	          waker: swapper/1
	127838

	target:          kworker/0:1
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa84df619 insert_work
	ffffffffa84e1102 __queue_work
	ffffffffa84e24e9 delayed_work_timer_fn
	ffffffffa85716fc call_timer_fn
	ffffffffa8572a5d __run_timers.part.0
	ffffffffa8572b7a run_timer_softirq
	ffffffffa94000d9 __softirqentry_text_start
	ffffffffa84c57b4 irq_exit_rcu
	          waker: swapper/0
	56152

	target:          wakeuptime
	ffffffffc086a887 nf_nat_locks
	ffffffffc086a887 nf_nat_locks
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa850381c sched_ttwu_pending
	ffffffffa858e797 flush_smp_call_function_queue
	ffffffffa858f2f3 generic_smp_call_function_single_interrupt
	ffffffffa847bf1d __sysvec_call_function_single
	ffffffffa919fc7b sysvec_call_function_single
	ffffffffa9200eeb asm_sysvec_call_function_single
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	ffffffffa91aed8e default_idle_call
	ffffffffa8508f89 cpuidle_idle_call
	          waker: swapper/1
	101
```

```
$ sudo ./wakeuptime -p 923 5
Tracing blocked time (us) by kernel stack

	target:          dockerd)
	ffffffffc0885e34 __this_module
	ffffffffc0885e34 __this_module
	ffffffffa862a874 bpf_trace_run1
	ffffffffa84f80f9 __bpf_trace_sched_wakeup_template
	ffffffffa8500e48 ttwu_do_wakeup
	ffffffffa8500f92 ttwu_do_activate
	ffffffffa8502ead try_to_wake_up
	ffffffffa8503275 wake_up_process
	ffffffffa8573492 hrtimer_wakeup
	ffffffffa8573a09 __hrtimer_run_queues
	ffffffffa8574821 hrtimer_interrupt
	ffffffffa84805b1 __sysvec_apic_timer_interrupt
	ffffffffa919fd0b sysvec_apic_timer_interrupt
	ffffffffa9200e4b asm_sysvec_apic_timer_interrupt
	ffffffffa91aec6b native_safe_halt
	ffffffffa844b8f5 arch_cpu_idle
	          waker: swapper/1
	10036
```
