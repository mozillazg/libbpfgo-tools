# mountsnoop

## build

```
make
```

## run

```
$ sudo ./mountsnoop
COMM             PID     TID     MNT_NS      CALL
umount           9088    9088    4026531841  umount("/media/abc", 0x0) = -EINVAL
umount           9091    9091    4026531841  umount("/dev/loop0", 0x0) = -EINVAL
umount           9091    9091    4026531841  umount("/media/abc", 0x0) = -EINVAL
mount            9094    9094    4026531841  mount("/dev/loop0", "/media/abc", "ext3", MS_SILENT, "") = -EACCES
mount            9094    9094    4026531841  mount("/dev/loop0", "/media/abc", "ext3", MS_RDONLY | MS_SILENT, "") = -EIO
mount            9097    9097    4026531841  mount("/dev/loop0", "/media/abc", "ext3", MS_SILENT, "") = -EACCES
mount            9097    9097    4026531841  mount("/dev/loop0", "/media/abc", "ext3", MS_RDONLY | MS_SILENT, "") = -EIO
mount            9100    9100    4026531841  mount("/dev/loop1", "/media/abc", "squashf", 0x0, "") = -EACCES
mount            9100    9100    4026531841  mount("/dev/loop1", "/media/abc", "squashf", MS_RDONLY, "") = 0
```

```
$ sudo ./mountsnoop  -d
PID:    9128
TID:    9128
COMM:   mount
OP:     MOUNT
RET:    -EACCES
LAT:    38us
MNT_NS: 4026531841
FS:     ext3
SOURCE: /dev/loop1
TARGET: /media/abc
DATA:
FLAGS:  MS_SILENT

PID:    9128
TID:    9128
COMM:   mount
OP:     MOUNT
RET:    -EIO
LAT:    5486us
MNT_NS: 4026531841
FS:     ext3
SOURCE: /dev/loop1
TARGET: /media/abc
DATA:
FLAGS:  MS_RDONLY | MS_SILENT

PID:    9131
TID:    9131
COMM:   umount
OP:     UMOUNT
RET:    -EINVAL
LAT:    19us
MNT_NS: 4026531841
FS:     xt3
SOURCE: dev/loop1
TARGET: /dev/loop1
DATA:
FLAGS:  0x0

PID:    9131
TID:    9131
COMM:   umount
OP:     UMOUNT
RET:    -EINVAL
LAT:    120us
MNT_NS: 4026531841
FS:     xt3
SOURCE: dev/loop1
TARGET: /media/abc
DATA:
FLAGS:  0x0
```
