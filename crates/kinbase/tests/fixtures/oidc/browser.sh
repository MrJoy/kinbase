#!/bin/bash
printf '%s\n' "$1" >> "@ARGV@"
[[ "$1" =~ redirect_uri=http(%3A|:)(%2F|/){2}127\.0\.0\.1(%3A|:)([0-9]+) ]]
port="${BASH_REMATCH[4]}"
[[ "$1" =~ state=([^&]*) ]]
state="${BASH_REMATCH[1]}"
get() { exec 3<>"/dev/tcp/127.0.0.1/${port}"; printf 'GET %s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n' "$1" "$port" >&3; resp="$(cat <&3 || true)"; exec 3<&-; exec 3>&-; printf '%s\n----\n' "$resp" >> "@HTTP@"; }
code="@CODE@"
case "@MODE@" in
  good) get "/callback?code=${code}&state=${state}" ;;
  bad-state) get "/callback?code=${code}&state=tampered-state"; get "/callback?code=${code}&state=${state}" ;;
  missing-state) get "/callback?code=${code}"; get "/callback?code=${code}&state=${state}" ;;
  error) get "/callback?error=access_denied&state=${state}" ;;
  no-code) get "/callback?state=${state}" ;;
  other) get "/not-callback"; get "/callback?code=${code}&state=${state}" ;;
  idle) exec 4<>"/dev/tcp/127.0.0.1/${port}"; get "/callback?code=${code}&state=${state}"; exec 4<&-; exec 4>&- ;;
esac
