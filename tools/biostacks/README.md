# biostacks

## build

```
make
```

## run

```
$ sudo ./biostacks
Tracing block I/O with init stacks. Hit Ctrl-C to end.
^Cjbd2/sd        286    sda
bpf_prog_18cd563033dabd37_blk_account_io_start
bpf_prog_18cd563033dabd37_blk_account_io_start
bpf_trampoline_6442511328_0
blk_account_io_start
__submit_bio
submit_bio_noacct
submit_bio
submit_bh_wbc
submit_bh
journal_submit_commit_record.part.0.constprop.0
jbd2_journal_commit_transaction
kjournald2
kthread
ret_from_fork
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 1        |****************************************|

jbd2/sd        286    sda
blk_account_io_merge_bio
blk_attempt_bio_merge.part.0
blk_attempt_plug_merge
blk_mq_submit_bio
__submit_bio
submit_bio_noacct
submit_bio
submit_bh_wbc
submit_bh
jbd2_journal_commit_transaction
kjournald2
kthread
ret_from_fork
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
fixed_percpu_data
     usecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 1        |****************************************|
```
