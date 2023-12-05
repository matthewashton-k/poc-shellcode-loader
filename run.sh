#!/bin/bash
cross build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/dll_deadlock.dll dll.dll
cross run --target x86_64-pc-windows-gnu --release --example loader