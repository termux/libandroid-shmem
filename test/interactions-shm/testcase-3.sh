./test-create-shm

IPC1=$(./test-create-ipc)
echo ${IPC1}
./shm-available.sh 1
IPC2=$(./test-create-ipc)
echo ${IPC2}
./shm-available.sh 1
IPC3=$(./test-create-ipc)
echo ${IPC3}
./shm-available.sh 1

./test-remove
./shm-available.sh 1
./test-remove ${IPC1}
./shm-available.sh 1
./test-remove ${IPC2}
./shm-available.sh 1
./test-remove ${IPC3}
./shm-available.sh 0
