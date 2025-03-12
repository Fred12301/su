# su

1. General Objective and Context

This code implements an advanced version of the su command for Android. Its purpose is to allow privilege escalation (switching to superuser mode) in a secure manner. It manages:

Permission verification via configuration files (database_check).

Communication with an external process (via a Unix socket) to exchange request-related information.

Preparation of the execution environment (variables, optional chroot, etc.).

Sending an intent (via the send_intent function) to notify of a request or result.

Advanced error handling, with retry mechanisms, wrappers for critical system calls, and configurable logging.



---

2. The su.h Header

This section defines the common interface used throughout the code:

Constants and Real Android Identifiers

AID_ROOT (0) and AID_SHELL (2000) are used to identify the root user and the shell, respectively.

Paths to application data (REQUESTOR_DATA_PATH, REQUESTOR_CACHE_PATH, etc.) are defined to locate configuration files and cache.


Intent Actions

ACTION_REQUEST and ACTION_RESULT define the actions used in broadcasts to signal an access request or its result.


Version and Protocol Parameters

VERSION, VERSION_CODE, DATABASE_VERSION, and PROTO_VERSION indicate version numbers to ensure compatibility.


Data Structures

su_initiator contains information about the process requesting privilege escalation (PID, UID, binary path, and arguments).

su_request groups the request parameters (target UID, login options, command to execute, etc.).

su_context combines the initiator and request, adding the umask value used for file creation.


Prototypes and Macros

External function prototypes, such as database_check and send_intent, are declared.

An inline function get_command returns the command to execute, either the specific command or the default shell.

Logging macros (PLOGE, PLOGEV) facilitate debugging by including error codes.

---

3. Global Variables and Configuration Parameters

Configurable Log Level

The variable su_log_level defines log verbosity (e.g., 3 for debug mode).


Dynamic Rule Storage Path

The variable runtime_stored_path holds the rules storage path. This path can be overridden by the SU_CONFIG_PATH environment variable, providing flexibility without recompilation.


Retry Mechanism for Socket Communication

The macro SOCKET_ACCEPT_RETRY (set to 3) allows multiple attempts in case of a timeout when accepting a socket connection.

---

4. The send_intent Function

This function is responsible for sending an intent via a system command to notify about a request or result:

Command Construction

The command is built using snprintf, leveraging Android’s am broadcast tool. It includes parameters such as the action, socket path, caller UID, authorization flag, and program version.


Environment Cleanup

Before executing the command, the function unsets sensitive environment variables that could influence linker behavior. Then, it restores a minimal LD_LIBRARY_PATH value to ensure the correct execution of am.


Restoring Effective Identifiers

The function resets effective and real identifiers (via setegid and seteuid) to prevent variables like LD_LIBRARY_PATH from being modified by Android 4.0+.


Execution

Finally, the command is executed using system(), and the result is returned.



---

5. Utility Functions

safe_read

A wrapper for read that ensures the requested number of bytes is read in a loop (useful for handling interruptions or partial reads).



---

6. Main Implementation (su.c)

a) Initialization and Retrieving Caller Process Information

from_init

This function reads /proc/<pid>/cmdline to retrieve the caller process's command line.

It also uses /proc/<pid>/exe to obtain the real binary path, replacing the name in the command if it's not app_process.

Arguments and the binary path are stored in the su_initiator structure.


b) Environment Preparation

populate_environment

If the environment preservation option (keepenv) is not enabled, this function retrieves the home directory and shell from the passwd file (via getpwuid) and sets environment variables (HOME, SHELL, USER, and LOGNAME).


c) Socket Communication Handling

socket_create_temp

Creates a temporary Unix socket in the application's cache folder. Before creation, it removes any existing socket to prevent conflicts.


socket_accept

Accepts an incoming socket connection. In case of a timeout or error, the function retries up to three times before giving up.


socket_send_request and socket_receive_result

These functions exchange data with the remote process. They send tokens (integers converted to network byte order via htonl) and read responses, ensuring structured communication.


d) Decision and Execution Functions

deny

Called to deny access. It sends a denial intent, logs the event, and displays an error on stderr before exiting.


allow

If access is granted, this function prepares the environment for command execution (adjusting UID and GID via setresuid/setresgid).

It also manages the "login shell" option by modifying the shell name (preceded by a hyphen if necessary).

If the SU_CHROOT environment variable is set, a chroot call is made for process isolation.

Finally, the command is executed using execv.


e) The main Function

Argument Handling

Uses getopt_long to parse command-line options such as --command, --shell, --login, --preserve-environment, --version, and a self-test option (--selftest).


Self-Test

If --selftest is detected, the run_selftest function is called to execute minimal unit test routines (to be expanded as needed).


Dynamic Configuration

The rules storage path is initialized by checking the SU_CONFIG_PATH environment variable. If defined and valid, this path is used instead of the default.


System Property Reading

The file /default.prop is read to get the ro.debuggable property. Similarly, /system/build.prop is read to retrieve information like ro.cm.version and ro.build.type.

These properties influence access verification logic (e.g., allowing root only on "debug" builds or based on certain parameters).


Security Checks

The code verifies that the caller process’s UID and other details (UID/GID of application files) are correct.

A check is performed via database_check, which reads a rule file (or uses a default configuration) to determine if access should be granted or denied.


Socket Communication and Final Decision

After establishing a socket and sending the request, the program waits for the external process’s response. Depending on the response (ALLOW or DENY), it calls allow or deny.

If the response is unknown or abnormal, access is denied.

---

7. Rule Verification with database_check

Dynamically constructs a rule file name based on the initiator and request UID.

Reads the file to compare the stored command with the current request.

Returns DB_ALLOW, DB_DENY, or DB_INTERACTIVE based on the file’s contents.

---

8. File Reading and Property Extraction Functions

read_file and get_property provide secure methods for reading system properties and configuration files.

---
