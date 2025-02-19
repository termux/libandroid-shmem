./test-create-shm

./test-create-shm && exit 1 || true
./shm-available.sh 1

./test-write
./test-read

./test-remove
./shm-available.sh 0
