set -eu


git pull ssh://nuttall.im/~psn/auth_webpy/ master || true
git commit -am checkpoint || true
git push ssh://nuttall.im/~psn/auth_webpy/ master
git push origin


