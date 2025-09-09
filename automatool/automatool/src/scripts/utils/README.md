# Utils Directory

This directory contains utility files and configurations for the automatool project.

## APK Unmask Ignore List

### File: `apk_unmask_ignore_list.txt`

This file contains regex patterns to filter out false positive detections from the `apk_unmask` tool. The automation will automatically load this file and use it to filter suspicious files that are actually benign.

### Format

Each line in the ignore list follows this format:
```
regex_pattern:reason_code:comment
```

- **regex_pattern**: A regular expression that matches file paths to ignore
- **reason_code**: A short code categorizing why this file is ignored (e.g., CRYPTO_LIB, CERT_FILE)
- **comment**: Human-readable explanation of what this pattern matches

### How to Add New Ignore Rules

1. **Identify the file path** from apk_unmask output that you want to ignore
2. **Create a regex pattern** that matches the file path
3. **Add the entry** to `apk_unmask_ignore_list.txt`

### Examples

#### Example 1: Ignore specific file
If apk_unmask detects `assets/config/app.properties` as suspicious but it's legitimate:
```
.*assets/config/app\.properties$:CONFIG_FILE:Application configuration file
```

#### Example 2: Ignore files with pattern
If you want to ignore all `.pem` certificate files in any directory:
```
.*\.pem$:CERT_FILE:Certificate files
```

#### Example 3: Ignore numbered files
If you want to ignore files like `data1.bin`, `data2.bin`, etc.:
```
.*data[0-9]+\.bin$:DATA_FILE:Numbered data files
```

### Regex Tips

- Use `.*` to match any characters
- Use `\.` to match literal dots (escape the dot)
- Use `$` to match end of string
- Use `[0-9]+` to match one or more numbers
- Use `[a-z]` to match lowercase letters
- Use `.*` at the beginning to match any path prefix

### Testing Your Patterns

Before adding patterns to the ignore list, you can test them using online regex testers or Python:

```python
import re
pattern = r".*lowmcL[0-9]+\.bin\.properties$"
test_path = "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties"
if re.match(pattern, test_path):
    print("Pattern matches!")
```

### Comments and Documentation

- Lines starting with `#` are comments and will be ignored
- Always add meaningful comments to explain what each pattern matches
- Use descriptive reason codes for better categorization

### Best Practices

1. **Be specific**: Make patterns as specific as possible to avoid false negatives
2. **Test thoroughly**: Verify patterns match intended files but not legitimate threats
3. **Document well**: Always include clear comments explaining the pattern
4. **Review regularly**: Periodically review and update patterns as needed
5. **Version control**: Keep changes to this file in version control with clear commit messages

### Automatic Loading

The automation will automatically:
- Load this file from the utils directory
- Parse all valid entries (ignoring comments and malformed lines)
- Apply the patterns during apk_unmask analysis
- Log any parsing errors for debugging

No configuration is needed - the system works out of the box once patterns are added to this file.
