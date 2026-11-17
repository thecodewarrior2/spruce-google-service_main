# S.P.R.U.C.E Mail Protection Service (0.6.9): the two repositories an installation downloads from, as
# deploy/settings.env names them (RELEASES_REPO: the approved versions; MODEL_REPO: the AI model's files). No
# default: each installation names its own. Sourced by install.sh, update.sh and upgrade.sh; the same rules as
# src/repos.js. EXAMPLE_* are only examples (the maintainer's repositories): use your own copies.
EXAMPLE_RELEASES_REPO=https://github.com/thecodewarrior2/spruce-google-service_main
EXAMPLE_MODEL_REPO=https://github.com/thecodewarrior2/tinyphishllm
# What's wrong with an address, or nothing: https only, no name or password, no ? or # part.
repo_problem() {
    local s="$1"
    [ -n "$s" ] || { echo "it is empty"; return; }
    case "$s" in
        *[[:space:]]*) echo "it has a space in it" ;;
        *@*) echo "it has a name or password in it (use a public repository)" ;;
        *'?'* | *'#'*) echo "it has a ? or # part" ;;
        https://*/*) ;;
        http://*) echo "only https:// addresses are used" ;;
        */*) case "$s" in */*/* | *:*) echo "it isn't https://… or OWNER/REPO" ;; esac ;;
        *) echo "it isn't https://… or OWNER/REPO" ;;
    esac
}
# The address to clone: OWNER/REPO is a GitHub repository (as RELEASES_REPO was written before 0.6.9).
repo_url() {
    local s="${1%/}"
    case "$s" in https://*) printf '%s' "$s" ;; */*) printf 'https://github.com/%s' "${s%.git}" ;; esac
}
