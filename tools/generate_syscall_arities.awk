BEGIN {
    record_separator = RS
    RS = "\n"
    while ((getline line < names_file) > 0) {
        if (line !~ /^SYSCALL\([0-9]+, [A-Za-z0-9_]+\)$/) {
            continue
        }
        entry = line
        sub(/^SYSCALL\(/, "", entry)
        sub(/\)$/, "", entry)
        split(entry, fields, /, /)
        number_by_name[fields[2]] = fields[1] + 0
        name_by_number[fields[1] + 0] = fields[2]
    }
    close(names_file)
    RS = record_separator
    print "/* Generated from Linux include/linux/syscalls.h by"
    print " * tools/generate_syscall_arities.awk. Do not edit by hand. */"
}

/asmlinkage long sys_[A-Za-z0-9_]+[ ]*\(/ {
    record = $0
    gsub(/[\n\t ]+/, " ", record)
    marker = "asmlinkage long sys_"
    position = index(record, marker)
    record = substr(record, position + length(marker))
    opening = index(record, "(")
    name = substr(record, 1, opening - 1)
    arguments = substr(record, opening + 1)
    closing = index(arguments, ")")
    arguments = substr(arguments, 1, closing - 1)

    if (!(name in number_by_name) || name in seen) {
        next
    }
    if (arguments == "void" || arguments == "") {
        arity = 0
    } else {
        arity = 1
        rest = arguments
        while (index(rest, ",") != 0) {
            rest = substr(rest, index(rest, ",") + 1)
            arity++
        }
    }
    arity_by_number[number_by_name[name]] = arity
    seen[name] = 1
}

END {
    for (number = 0; number < 1024; number++) {
        if (number in arity_by_number) {
            printf "ARITY(%d, %d, %s)\n", number, arity_by_number[number], \
                   name_by_number[number]
        }
    }
}
