echo "Due to the nature of this task, creating unit/integration tests are very difficult."
echo "Instead, this test script presents a few real-world test cases."
echo "Test start!"

set -x

echo "\n\nSimple ping."
timeout 10 ./9S cloudflare.com

echo "\n\nPing, but use a short ttl. Expect Time Exceeded packets."
timeout 10 ./9S --ttl 1 cloudflare.com

echo "\n\nPing localhost."
timeout 10 ./9S localhost

echo "\n\nPing using raw IPv4 address."
timeout 10 ./9S 127.0.0.1

echo "\n\nPing using raw IPv6 address."
timeout 10 ./9S blog.cloudflare.com

echo "\n\nPing, but use a short timeout. Expect no output until the end."
timeout 10 ./9S --timeout 10 nierautomata.square-enix-games.com

echo "\n\nSend only 3 packets."
timeout 10 ./9S --iter 3 cloudflare.com

echo "\n\nTwo processes each doing their own ping. Expect only one packet to be received every second!"
timeout 10 ./9S cloudflare.com &
echo "\n"
timeout 10 ./9S cloudflare.com
wait

echo "\n\nTest done!"

set +x
