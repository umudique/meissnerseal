# GDB Procedures for Arcanum Security Lab

**Status:** Skeleton — fill before first lab activation (MVP-2)

## Memory Inspection After Session Lock

```gdb
# Attach to running arcanum process
gdb -p <pid>

# Inspect memory region of VaultSession
# [procedure to be documented after implementation]

# Dump memory to file for analysis
dump memory /tmp/arcanum-memdump.bin 0xADDRESS 0xADDRESS+0x1000
```

## Zeroization Verification (Scenario 009)

```gdb
# Set breakpoint after lock_vault() returns
# Inspect memory regions that held vault root key
# Verify contents are zeroed
# [exact addresses documented after MVP-0 implementation]
```

## Timing Measurement (Scenario 005)

```gdb
# Use GDB scripting to measure function execution time
# Compare timing across different secret inputs
# [procedure to be documented]
```
