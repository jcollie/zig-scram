# SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

# The tool takes no file arguments — it reads the password from stdin — so
# suppress fish's default filename completion.
complete -c scram-sha-256 -f

complete -c scram-sha-256 -s p -l password -r -d 'Use TEXT instead of reading stdin (visible to other processes)'
complete -c scram-sha-256 -s i -l iterations -x -d 'PBKDF2 rounds (default 4096)'
complete -c scram-sha-256 -s s -l salt-length -x -d 'Random salt bytes (default 16)'
complete -c scram-sha-256 -l raw -d 'Skip SASLprep and use the password bytes as given'
complete -c scram-sha-256 -l strict-prep -d 'Fail instead of falling back to raw bytes when SASLprep rejects'
complete -c scram-sha-256 -s h -l help -d 'Show the usage message'
