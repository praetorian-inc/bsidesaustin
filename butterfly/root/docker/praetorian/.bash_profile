# Personal commands
alias ls='ls -G'
alias l='ls -Gl'
alias ll='ls -Gla '
alias sl=ls
alias dc=cd
alias i=ipython

# Reload bash_profile
alias reload='source ~/.bash_profile'

# Windows commands
alias cls=clear
alias copy=cp
alias move=mv
alias del=rm
alias dir=ls
alias findstr=grep

alias tmux='export TERM=screen-256color; tmux -2'

alias ips='ip a'

export PYENV_ROOT="${HOME}/.pyenv"

if [ -d "${PYENV_ROOT}" ]; then
    export PATH="${PYENV_ROOT}/bin:${PATH}"
    eval "$(pyenv init -)"
fi

source ~/.bashrc
