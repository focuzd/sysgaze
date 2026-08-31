$2 == "sysgaze-filtered" {
    ordinary_ptrace[$1] = $9 + 0
}

$2 == "sysgaze-seccomp" {
    workload_count++
    workloads[workload_count] = $1
    sysgaze_ms[$1] = $3 + 0
    seccomp_ptrace[$1] = $9 + 0
}

$2 == "strace-filtered" {
    strace_ms[$1] = $3 + 0
    has_strace = 1
}

END {
    print "Smoke benchmark: 1 warmup + 1 measured sample (indicative only)"
    print "Filter: trace=getpid"
    if (has_strace) {
        printf "%-9s %12s %12s %11s %17s\n", "workload", "sysgaze-ms",
               "strace-ms", "vs-strace", "ptrace reduction"
    } else {
        print "strace: not installed; comparison omitted"
        printf "%-9s %12s %17s\n", "workload", "sysgaze-ms",
               "ptrace reduction"
    }
    for (position = 1; position <= workload_count; ++position) {
        name = workloads[position]
        reduction = ordinary_ptrace[name] == 0 ? 0 :
            100 * (1 - seccomp_ptrace[name] / ordinary_ptrace[name])
        if (has_strace) {
            difference = strace_ms[name] == 0 ? 0 :
                100 * (sysgaze_ms[name] / strace_ms[name] - 1)
            printf "%-9s %12.3f %12.3f %+10.1f%% %16.1f%%\n", name,
                   sysgaze_ms[name], strace_ms[name], difference, reduction
        } else {
            printf "%-9s %12.3f %16.1f%%\n", name, sysgaze_ms[name],
                   reduction
        }
    }
    print "Sysgaze mode: seccomp-filtered; strace mode: ordinarily filtered."
    print "Negative vs-strace values mean Sysgaze was faster in this sample."
    print "Ptrace reduction is relative to ordinary Sysgaze filtering."
    print "Use 'make bench-compare' for 30-sample measurements."
}
