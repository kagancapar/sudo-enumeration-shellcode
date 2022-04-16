# about sudo

![Sudo_logo](https://user-images.githubusercontent.com/33525376/163675209-16de0aff-99da-49f8-9e59-b0e85a076766.png)

Sudo (su “do”) allows a system administrator to give certain users (or groups of users) the ability to run some (or all) commands as root while logging all commands and arguments. Sudo operates on a per-command basis, it is not a replacement for the shell. Its features include:

The ability to restrict what commands a user may run on a per-host basis.

Sudo does copious logging of each command, providing a clear audit trail of who did what. When used in tandem with syslogd, the system log daemon, sudo can log all commands to a central host (as well as on the local host). At CU, all admins use sudo in lieu of a root shell to take advantage of this logging.

Sudo uses timestamp files to implement a “ticketing” system. When a user invokes sudo and enters their password, they are granted a ticket for 5 minutes (this timeout is configurable at compile-time). Each subsequent sudo command updates the ticket for another 5 minutes. This avoids the problem of leaving a root shell where others can physically get to your keyboard. There is also an easy way for a user to remove their ticket file, useful for placing in a .logout file.

Sudo’s configuration file, the sudoers file, is setup in such a way that the same sudoers file may be used on many machines. This allows for central administration while keeping the flexibility to define a user’s privileges on a per-host basis. Please see the samples sudoers file below for a real-world example.



# about sudo-enumeration-shellcode

This developed shellcode checks whether the sudo running on the operating system has the current public vulnerability.
