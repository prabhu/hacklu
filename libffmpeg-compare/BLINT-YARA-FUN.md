Self-explanatory yara rules possible with blint metadata.

```yara
condition:
  blint.binary_type == "ELF" and
  (
      not blint.has_nx or
      not blint.has_canary
  )
```

```yara
condition:
  blint.binary_type == "ELF" and blint.relro == "partial"
```

```yara
condition:
  blint.first_stage_symbols and (length(blint.first_stage_symbols) > 0)
```

```yara
meta:
  vulnerable_module = "github.com/example/vulnerable-lib"
  vulnerable_version_prefix = "v1.2."
condition:
  blint.go_dependencies[vulnerable_module] and
  blint.go_dependencies[vulnerable_module].version starts with vulnerable_version_prefix
```

```yara
condition:
  blint.binary_type == "PE" and blint.resources and blint.resources.has_manifest and
  (
      // Search for keywords in the manifest XML content.
      "autoElevate" in blint.resources.manifest or
      "requireAdministrator" in blint.resources.manifest or
      "asInvoker" in blint.resources.manifest
  )
```

```
condition:
  blint.binary_type == "PE" and blint.authenticode and
  blint.authenticode.verification_flags != "OK"
```

```
condition:
  blint.binary_type == "MachO" and blint.is_neural_model
```
