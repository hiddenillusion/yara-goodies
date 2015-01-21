data=$1
cnt=0

cat $data | while read line; do
        echo '$s'$cnt' = ' \"$line\"
        ((cnt += 1))
done