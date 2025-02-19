./test-create-shm

./check-attachments.sh

./test-endless-attachment &
./check-attachments.sh

./test-endless-attachment &
./check-attachments.sh

./test-remove
./shm-available.sh yes

kill $(pidof -s test-endless-attachment)
./shm-available.sh 1

./test-write
./test-read

kill $(pidof -s test-endless-attachment)
./shm-available.sh 0
