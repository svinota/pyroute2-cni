#!/bin/sh

case "$1" in
  cni)
    exec /usr/local/bin/pyroute2-cni
    ;;
  cm)
    exec /usr/local/bin/pyroute2-cm
    ;;
  *)
    exec /usr/local/bin/pyroute2-cni
    ;;
esac
