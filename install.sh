#!/usr/bin/env bash
# install_termux.sh — jschat installer for Termux
# usage: bash install_termux.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="jschat"

# termux prefix
# Termux sets $PREFIX; fall back to the standard path if running elsewhere
if [[ -n "${PREFIX}" && -d "${PREFIX}" ]]; then
    IS_TERMUX=1
    BIN_DIR="${PREFIX}/bin"
    BASH_COMP_DIR="${PREFIX}/etc/bash_completion.d"
    ZSH_COMP_DIR="${PREFIX}/share/zsh/site-functions"
    MAN_DIR="${PREFIX}/share/man/man1"
    FISH_COMP_DIR="${HOME}/.config/fish/completions"
else
    IS_TERMUX=0
    BIN_DIR="/usr/local/bin"
    BASH_COMP_DIR="/etc/bash_completion.d"
    ZSH_COMP_DIR="/usr/share/zsh/vendor-completions"
    MAN_DIR="/usr/local/share/man/man1"
    FISH_COMP_DIR="${HOME}/.config/fish/completions"
fi

INSTALL_BIN="${BIN_DIR}/${BINARY_NAME}"

# root check
if [[ "${IS_TERMUX}" -eq 0 && "${EUID}" -ne 0 ]]; then
    echo "error: run as root on Linux (sudo ./install_termux.sh)"
    exit 1
fi

# dependency check and install
if [[ "${IS_TERMUX}" -eq 1 ]]; then
    echo "→ checking Termux dependencies..."

    MISSING=()
    command -v clang++  &>/dev/null || MISSING+=("clang")
    command -v make     &>/dev/null || MISSING+=("make")
    # openssl headers — check for the pkg-config entry or the header itself
    if ! pkg-config --exists openssl 2>/dev/null && \
       [[ ! -f "${PREFIX}/include/openssl/evp.h" ]]; then
        MISSING+=("openssl")
    fi

    if [[ ${#MISSING[@]} -gt 0 ]]; then
        echo "→ installing missing packages: ${MISSING[*]}"
        pkg install -y "${MISSING[@]}"
    else
        echo "   all dependencies present"
    fi
fi

# build
if [[ ! -f "${SCRIPT_DIR}/build/${BINARY_NAME}" ]]; then
    echo "→ binary not found — building..."
    # Makefile auto-detects Termux via $PREFIX — same command everywhere
    ( cd "${SCRIPT_DIR}" && make )
else
    echo "→ binary already built — skipping compile"
fi

# fix for first builds
if [[ "${IS_TERMUX}" -eq 0 ]]; then
    DESKTOP_FILE="/usr/share/applications/${BINARY_NAME}.desktop"
    if [[ -f "${DESKTOP_FILE}" ]]; then
        echo "→ removing desktop entry ${DESKTOP_FILE}"
        rm -f "${DESKTOP_FILE}"
        update-desktop-database /usr/share/applications 2>/dev/null || true
    fi

    ICON_FILE="/usr/share/icons/hicolor/256x256/apps/${BINARY_NAME}.png"
    if [[ -f "${ICON_FILE}" ]]; then
        echo "→ removing icon ${ICON_FILE}"
        rm -f "${ICON_FILE}"
        gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
    fi
fi

# install binary
echo "→ installing binary to ${INSTALL_BIN}"
mkdir -p "${BIN_DIR}"
install -m 755 "${SCRIPT_DIR}/build/${BINARY_NAME}" "${INSTALL_BIN}"

# bash completion
echo "→ installing bash completion"
mkdir -p "${BASH_COMP_DIR}"
cat > "${BASH_COMP_DIR}/${BINARY_NAME}" <<'BASH'
_jschat_complete() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${COMP_CWORD}" in
        1)
            COMPREPLY=( $(compgen -W "-s -c -h --help" -- "${cur}") )
            ;;
        2)
            case "${prev}" in
                -s)
                    COMPREPLY=( $(compgen -W "5050 7777 8080 9000" -- "${cur}") )
                    ;;
                -c)
                    local hosts="127.0.0.1 localhost"
                    [[ -f ~/.jschat_hosts ]] && hosts="${hosts} $(cat ~/.jschat_hosts)"
                    COMPREPLY=( $(compgen -W "${hosts}" -- "${cur}") )
                    ;;
            esac
            ;;
        3)
            COMPREPLY=()
            ;;
        4)
            case "${COMP_WORDS[1]}" in
                -c)
                    local nicks="$(whoami)"
                    [[ -f ~/.jschat_nicks ]] && nicks="${nicks} $(cat ~/.jschat_nicks)"
                    COMPREPLY=( $(compgen -W "${nicks}" -- "${cur}") )
                    ;;
            esac
            ;;
    esac
}
complete -F _jschat_complete jschat
BASH

# zsh completion
echo "→ installing zsh completion"
mkdir -p "${ZSH_COMP_DIR}"
cat > "${ZSH_COMP_DIR}/_${BINARY_NAME}" <<'ZSH'
#compdef jschat

_jschat() {
    local state

    _arguments \
        '(-h --help)'{-h,--help}'[show help]' \
        '-s[start server]: :->server_args' \
        '-c[connect as client]: :->client_args' \
        && return 0

    case $state in
        server_args)
            _arguments \
                '1:port:(5050 7777 8080 9000)' \
                '2:passphrase:( )'
            ;;
        client_args)
            _arguments \
                '1:host:(127.0.0.1 localhost)' \
                '2:passphrase:( )' \
                '3:nickname:($(whoami))'
            ;;
    esac
}

_jschat "$@"
ZSH

# fish completion
if command -v fish &>/dev/null; then
    echo "→ installing fish completion"
    mkdir -p "${FISH_COMP_DIR}"
    cat > "${FISH_COMP_DIR}/jschat.fish" <<'FISH'
complete -c jschat -f
complete -c jschat -s h -l help -d "show help"
complete -c jschat -s s         -d "start server"      -r
complete -c jschat -s c         -d "connect as client"  -r

complete -c jschat -n "__fish_seen_subcommand_from -s" \
    -a "5050 7777 8080 9000" -d "port"

complete -c jschat -n "__fish_seen_subcommand_from -c" \
    -a "127.0.0.1 localhost" -d "host"
FISH
else
    echo "   fish not found — skipping"
fi

# man page
echo "→ installing man page"
mkdir -p "${MAN_DIR}"
cat > "${MAN_DIR}/jschat.1" <<'MAN'
.TH JSCHAT 1 "" "jschat" "User Commands"
.SH NAME
jschat \- encrypted terminal chat (AES\-256\-GCM)
.SH SYNOPSIS
.B jschat
.B \-s
.I port passphrase
.br
.B jschat
.B \-c
.I host passphrase nickname
.br
.B jschat
.B \-h
.SH DESCRIPTION
.B jschat
is a lightweight peer-to-peer terminal chat tool.
All messages are encrypted with AES\-256\-GCM.
The passphrase is used to derive a 32-byte key via SHA\-256.
.SH OPTIONS
.TP
.B \-s \fIport\fR \fIpassphrase\fR
Start a server on the given port.
.TP
.B \-c \fIhost\fR \fIpassphrase\fR \fInickname\fR
Connect to a server. \fIhost\fR may include port as \fIhost:port\fR (default: 5050).
.TP
.B \-h, \-\-help
Print usage and exit.
.SH EXAMPLES
.B jschat \-s 5050 mysecret
.br
.B jschat \-c 127.0.0.1 mysecret alice
.br
.B jschat \-c 192.168.1.5:7777 mysecret bob
.SH IN-SESSION COMMANDS
.TP
.B /quit
Disconnect gracefully.
.TP
.B /who
Show your nickname.
.TP
.B /help
List commands.
.SH ENVIRONMENT
.TP
.B JSCHAT_PORT
Override default port (client mode).
.TP
.B JSCHAT_TIMEOUT
Connection timeout in seconds (default: 10).
.TP
.B JSCHAT_RECONNECT
Reconnect attempts (default: 3).
.TP
.B JSCHAT_MAX_CLIENTS
Max clients in server mode (default: 32).
.TP
.B JSCHAT_HEARTBEAT
Heartbeat interval in seconds (default: 15).
.SH FILES
.TP
.B ~/.jschat_hosts
Hosts for shell tab-completion.
.TP
.B ~/.jschat_nicks
Nicknames for shell tab-completion.
.SH SECURITY
AES\-256\-GCM with a fresh random IV per message. Pre-shared passphrase model.
MAN

# update man db
if [[ "${IS_TERMUX}" -eq 0 ]]; then
    mandb 2>/dev/null || true
fi

# done
echo ""
echo "✓ done"
echo ""
echo "usage:"
echo "  jschat -s 5050 passphrase"
echo "  jschat -c 127.0.0.1 passphrase nickname"
echo ""

if [[ "${IS_TERMUX}" -eq 1 ]]; then
    echo "activate bash completion (add to ~/.bashrc to make permanent):"
    echo "  source ${BASH_COMP_DIR}/${BINARY_NAME}"
    echo ""
    echo "note: Termux doesn't support man — read docs with:"
    echo "  jschat -h"
else
    echo "activate bash completion:"
    echo "  source ${BASH_COMP_DIR}/${BINARY_NAME}"
    echo "  man jschat"
fi
echo ""