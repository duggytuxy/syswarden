import os
import re

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    modified = False
    for i, line in enumerate(lines):
        # We want to match things like:
        #   os.Remove("...")
        #   exec.Command("...").Run()
        #   cmd.Start()
        #   cmd.Wait()
        #   f.WriteString(...)
        # But we do NOT want to match:
        #   _ = os.Remove("...")
        #   err = os.Remove("...")
        #   err := os.Remove("...")
        #   if err := os.Remove("..."); err != nil {
        #   return os.Remove("...")
        
        stripped = line.lstrip()
        
        if stripped.startswith("_ = ") or stripped.startswith("err =") or stripped.startswith("err :=") or "err := " in stripped or stripped.startswith("return "):
            continue

        if stripped.startswith("defer "):
            # handle defer f.Close() -> defer func() { _ = f.Close() }()
            if re.match(r'^defer\s+[a-zA-Z0-9_.]+\.Close\(\)$', stripped):
                spaces = len(line) - len(stripped)
                call = stripped[len("defer "):]
                lines[i] = (" " * spaces) + f"defer func() {{ _ = {call} }}()\n"
                modified = True
            continue

        # For function calls that return errors that we want to ignore
        patterns = [
            r'^(os\.Remove\([^)]+\))$',
            r'^(os\.RemoveAll\([^)]+\))$',
            r'^(os\.MkdirAll\([^)]+\))$',
            r'^(os\.Chmod\([^)]+\))$',
            r'^(os\.WriteFile\([^)]+\))$',
            r'^(exec\.Command\([^)]+\)\.Run\(\))$',
            r'^(exec\.CommandContext\([^)]+\)\.Run\(\))$',
            r'^([a-zA-Z0-9_]+\.Start\(\))$',
            r'^([a-zA-Z0-9_]+\.Wait\(\))$',
            r'^(http\.Post\([^)]+\))$',
            r'^([a-zA-Z0-9_]+\.WriteString\([^)]+\))$',
            r'^([a-zA-Z0-9_]+\.Close\(\))$',
            r'^([a-zA-Z0-9_]+\.SetDeadline\([^)]+\))$',
            r'^(io\.Copy\([^)]+\))$',
            r'^(fmt\.Sscanf\([^)]+\))$',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, stripped)
            if match:
                spaces = len(line) - len(stripped)
                lines[i] = (" " * spaces) + "_ = " + match.group(1) + "\n"
                modified = True
                break

    if modified:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        print(f"Fixed {filepath}")

def main():
    for root, dirs, files in os.walk(r"C:\Users\duggyt\DevOps\syswarden\src\core"):
        for file in files:
            if file.endswith(".go"):
                process_file(os.path.join(root, file))

if __name__ == "__main__":
    main()
