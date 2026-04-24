##! Zeek base config for the yaler lab middlebox

@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/dns
@load base/frameworks/notice

# Reduce noise: don't log DNS, focus on TCP/TLS/HTTP
redef LogAscii::use_json = T;

# Docker virtual interfaces use NIC checksum offloading; checksums are invalid inside the container
redef ignore_checksums = T;
