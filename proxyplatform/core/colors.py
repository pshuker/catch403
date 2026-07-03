"""ANSI colour codes and status-line prefixes used across proxyplatform modules."""

# Formatting
bold      = "\033[1m"
underline = "\033[4m"
end       = "\033[0m"

# Colours
red    = "\033[91m"
green  = "\033[92m"
yellow = "\033[93m"
blue   = "\033[94m"
white  = "\033[97m"

# Status prefixes
run  = f"{bold}{blue}[*]{end}"
good = f"{bold}{green}[+]{end}"
bad  = f"{bold}{red}[-]{end}"
info = f"{bold}{white}[!]{end}"
que  = f"{bold}{yellow}[?]{end}"
tab  = "    "
