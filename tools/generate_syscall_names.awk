BEGIN {
    if (syscall_limit !~ /^[0-9]+$/ || syscall_limit + 0 <= 0) {
        print "syscall_limit must be a positive integer" > "/dev/stderr"
        exit 1
    }
    print "/* Generated from Linux asm/unistd_64.h by"
    print " * tools/generate_syscall_names.awk. Do not edit by hand. */"
    previous = -1
    count = 0
}

$1 == "#define" && $2 ~ /^__NR_[A-Za-z0-9_]+$/ && $3 ~ /^[0-9]+$/ {
    name = substr($2, 6)
    number = $3 + 0
    if (number <= previous) {
        print "syscall numbers are not strictly increasing" > "/dev/stderr"
        exit 1
    }
    if (number >= syscall_limit) {
        print "syscall number exceeds SG_SYSCALL_LIMIT" > "/dev/stderr"
        exit 1
    }
    printf "SYSCALL(%d, %s)\n", number, name
    previous = number
    count++
}

END {
    if (count == 0) {
        print "no x86-64 syscall definitions found" > "/dev/stderr"
        exit 1
    }
}
