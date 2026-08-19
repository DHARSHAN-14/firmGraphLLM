"""
FirmGraph-LLM — One-Shot Examples for Sink/Source Identification
=================================================================
Few-shot examples injected into sink and source identification prompts,
exactly as described in the LATTE paper (Section 3.2).

These examples guide the LLM to produce consistently structured JSON
output for any external function name it is asked to classify.
"""

# ── Sink Examples ─────────────────────────────────────────────────────────────

SINK_EXAMPLES: list[dict] = [
    {
        "function": "system",
        "is_sink": True,
        "vulnerable_params": [0],
        "cwe_types": ["CWE-78"],
        "reason": (
            "system() executes a shell command passed as its first argument. "
            "If the argument contains attacker-controlled data, an OS command "
            "injection vulnerability (CWE-78) occurs."
        ),
    },
    {
        "function": "execl",
        "is_sink": True,
        "vulnerable_params": [0, 1],
        "cwe_types": ["CWE-78"],
        "reason": (
            "execl() replaces the current process image with a new program. "
            "Parameters 0 (path) and 1 (arg0) are dangerous if tainted, "
            "enabling OS command injection (CWE-78)."
        ),
    },
    {
        "function": "popen",
        "is_sink": True,
        "vulnerable_params": [0],
        "cwe_types": ["CWE-78"],
        "reason": (
            "popen() opens a process by creating a pipe and forking. "
            "The command string (param 0) is passed to /bin/sh -c, making "
            "it a command injection sink (CWE-78)."
        ),
    },
    {
        "function": "strcpy",
        "is_sink": True,
        "vulnerable_params": [0, 1],
        "cwe_types": ["CWE-120"],
        "reason": (
            "strcpy() copies a string without bounds checking. If the source "
            "(param 1) is tainted and longer than the destination buffer "
            "(param 0), a buffer overflow occurs (CWE-120)."
        ),
    },
    {
        "function": "strcat",
        "is_sink": True,
        "vulnerable_params": [0, 1],
        "cwe_types": ["CWE-120"],
        "reason": (
            "strcat() appends a string without size validation. Tainted input "
            "in param 1 can overflow the destination buffer (CWE-120)."
        ),
    },
    {
        "function": "sprintf",
        "is_sink": True,
        "vulnerable_params": [0, 1],
        "cwe_types": ["CWE-120", "CWE-134"],
        "reason": (
            "sprintf() writes formatted output without size limits. "
            "If the format string (param 1) is tainted, it enables format "
            "string attacks (CWE-134); if the output buffer overflows, CWE-120."
        ),
    },
    {
        "function": "printf",
        "is_sink": True,
        "vulnerable_params": [0],
        "cwe_types": ["CWE-134"],
        "reason": (
            "printf() with a user-controlled format string (param 0) enables "
            "format string attacks (CWE-134) including arbitrary read/write."
        ),
    },
    {
        "function": "memcpy",
        "is_sink": True,
        "vulnerable_params": [0, 1, 2],
        "cwe_types": ["CWE-120"],
        "reason": (
            "memcpy() copies n bytes from source to destination without bounds "
            "checking. A tainted size (param 2) or source (param 1) can cause "
            "buffer overflow (CWE-120)."
        ),
    },
    {
        "function": "gets",
        "is_sink": True,
        "vulnerable_params": [0],
        "cwe_types": ["CWE-120"],
        "reason": (
            "gets() reads input with no length limit — it is always a "
            "buffer overflow sink (CWE-120). Deprecated in C11."
        ),
    },
    {
        "function": "fprintf",
        "is_sink": True,
        "vulnerable_params": [1],
        "cwe_types": ["CWE-134"],
        "reason": (
            "fprintf() with a tainted format string (param 1) enables "
            "format string exploitation (CWE-134)."
        ),
    },
    {
        "function": "malloc",
        "is_sink": False,
        "vulnerable_params": [],
        "cwe_types": [],
        "reason": (
            "malloc() allocates memory; it is not itself a taint sink "
            "because reaching it with tainted data does not directly cause "
            "a vulnerability at the call site."
        ),
    },
]

# ── Source Examples ───────────────────────────────────────────────────────────

SOURCE_EXAMPLES: list[dict] = [
    {
        "function": "recv",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "recv() reads data from a network socket into a buffer (param 1). "
            "Network data is attacker-controllable, making param 1 a taint source."
        ),
    },
    {
        "function": "recvfrom",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "recvfrom() receives a message from a socket. The data buffer "
            "(param 1) receives attacker-controlled network data."
        ),
    },
    {
        "function": "read",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "read() reads from a file descriptor into a buffer (param 1). "
            "When the fd is a socket or stdin, the data is externally controlled."
        ),
    },
    {
        "function": "fgets",
        "is_source": True,
        "output_params": [0],
        "reason": (
            "fgets() reads a line from a stream into the buffer at param 0. "
            "Reading from stdin or a file makes this a taint source."
        ),
    },
    {
        "function": "fscanf",
        "is_source": True,
        "output_params": [2],
        "reason": (
            "fscanf() reads formatted input from a stream. The output "
            "arguments (from param 2 onward) receive external data."
        ),
    },
    {
        "function": "scanf",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "scanf() reads formatted input from stdin. Output arguments "
            "(from param 1 onward) are taint sources."
        ),
    },
    {
        "function": "getenv",
        "is_source": True,
        "output_params": [-1],  # return value
        "reason": (
            "getenv() returns the value of an environment variable. "
            "Environment variables can be set by attackers, so the return "
            "value is a taint source."
        ),
    },
    {
        "function": "SSL_read",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "SSL_read() reads data from a TLS connection into the buffer "
            "(param 1). TLS data originates from an external peer."
        ),
    },
    {
        "function": "BIO_read",
        "is_source": True,
        "output_params": [1],
        "reason": (
            "BIO_read() reads data from an OpenSSL BIO into a buffer "
            "(param 1). BIO wraps I/O sources including network sockets."
        ),
    },
    {
        "function": "strlen",
        "is_source": False,
        "output_params": [],
        "reason": (
            "strlen() returns the length of a string. It does not introduce "
            "new external data — it is not a taint source."
        ),
    },
]
