printf "Due to the nature of this task, creating unit/integration tests are very difficult.\n"
printf "Instead, this test script presents a few real-world test cases.\n"
printf "Tests start!\n"

printf "\n\nSimple ping.\n"
timeout 5 ./9S cloudflare.com
sleep 1

printf "\n\nPing, but use a short ttl. Expect Time Exceeded packets.\n"
timeout 5 ./9S --ttl 1 cloudflare.com
sleep 1

printf "\n\nPing localhost.\n"
timeout 5 ./9S localhost
sleep 1

printf "\n\nPing using raw IPv4 address.\n"
timeout 5 ./9S 127.0.0.1
sleep 1

printf "\n\nPing using raw IPv6 address.\n"
timeout 5 ./9S ::1
sleep 1

printf "\n\nPing, but must use IPv6 address.\n"
timeout 5 ./9S -6 ip6-localhost
sleep 1

printf "\n\nPing, but hostname should be automatically resolved to be IPv6.\n"
timeout 5 ./9S ip6-localhost
sleep 1

printf "\n\nPing, but use an extremely short timeout. Expect packets to timeout.\n"
timeout 5 ./9S --timeout 10 nierautomata.square-enix-games.com
sleep 1

printf "\n\nSend only 3 packets.\n"
timeout 5 ./9S --iter 3 cloudflare.com
wait
sleep 1

printf "\n\nTwo processes each doing their own ping. Expect only 5 packets per process!\n"
timeout 5 ./9S cloudflare.com &
timeout 5 ./9S cloudflare.com
wait
sleep 1

printf "\n\nTests done!\n"
