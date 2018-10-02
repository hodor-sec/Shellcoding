cat {ASMFILE} | awk {'print $2'} | sed 's/.\{2\}/\\x&/g' | paste -d '' -s | sed 's/^/"/'|sed 's/$/"/g'
