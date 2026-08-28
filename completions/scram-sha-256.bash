# SPDX-FileCopyrightText: 2026 Jeffrey C. Ollie <jeff@ocjtech.us>
# SPDX-License-Identifier: MIT

_scram_sha_256() {
    local cur prev opts
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}

    # A password or a number: nothing sensible to offer, and completing a
    # password against the filesystem would be worse than offering nothing.
    case "$prev" in
        -p | --password | -i | --iterations | -s | --salt-length)
            return 0
            ;;
    esac

    opts='-p --password -i --iterations -s --salt-length --raw --strict-prep -h --help'

    if [[ $cur == -* ]]; then
        mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$cur")
    fi

    return 0
}

# No -o default: the tool takes no file arguments, so falling back to filename
# completion would only ever produce an unrecognized argument.
complete -F _scram_sha_256 scram-sha-256
