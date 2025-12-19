# SIGKILL Cleanup Tests

This directory contains end-to-end tests for verifying process cleanup when the main ProcessManager process receives a SIGKILL (or equivalent forceful termination).

## Overview

The SIGKILL cleanup tests use a multi-process architecture to verify that child processes are properly cleaned up when the ProcessManager host process is forcefully terminated:

1. **Test Orchestrator** (`sigkill_cleanup_test.rs`) - The main test process that manages the test scenario
2. **Victim Process** (`../examples/sigkill_victim.rs`) - A separate executable that runs ProcessManager and spawns children
3. **Target Child Pro